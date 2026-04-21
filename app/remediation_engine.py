from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Sequence, Tuple

import requests

from fod_aviator import AviatorGuidance, FileRemediation, FoDAviatorClient, severity_rank


class PatchApplyError(Exception):
    pass


@dataclass
class QualityGate:
    min_severity_rank: int = 4
    require_guidance_available: bool = True
    require_file_changes: bool = True
    require_changed_file: bool = True
    allow_multi_file_changes: bool = True


VALID_SEVERITY_STRINGS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
FIX_BRANCH_PREFIX = "fortify-aviator-fix-"


def load_local_env_file() -> None:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"").strip("'")
        if key:
            os.environ.setdefault(key, value)


def configured_severity_strings() -> List[str]:
    raw_value = os.environ.get("FOD_SEVERITY_STRINGS", "Critical").strip()
    if not raw_value:
        return []

    severities: List[str] = []
    invalid: List[str] = []
    for token in raw_value.split(","):
        normalized = token.strip().lower()
        if not normalized:
            continue
        canonical = VALID_SEVERITY_STRINGS.get(normalized)
        if canonical is None:
            invalid.append(token.strip())
            continue
        if canonical not in severities:
            severities.append(canonical)

    if invalid:
        allowed = ", ".join(VALID_SEVERITY_STRINGS.values())
        raise RuntimeError(f"Unsupported FOD_SEVERITY_STRINGS value(s): {', '.join(invalid)}. Allowed values: {allowed}")

    return severities


def normalize_repo_path(value: str) -> str:
    return Path(value).as_posix().lstrip("./")


def parse_github_repository(value: str) -> str:
    remote = value.strip()
    patterns = (
        r"^https://github\.com/([^/]+/[^/]+?)(?:\.git)?$",
        r"^git@github\.com:([^/]+/[^/]+?)(?:\.git)?$",
        r"^ssh://git@github\.com/([^/]+/[^/]+?)(?:\.git)?$",
    )
    for pattern in patterns:
        match = re.match(pattern, remote)
        if match:
            return match.group(1)
    return ""


def git_origin_repository(repo_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    return parse_github_repository(result.stdout.strip())


def git_ref_names(repo_root: Path, ref_prefix: str) -> List[str]:
    try:
        result = subprocess.run(
            ["git", "for-each-ref", "--format=%(refname:short)", ref_prefix],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    refs = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if ref_prefix == "refs/remotes/origin":
        return [ref.removeprefix("origin/") for ref in refs if ref.startswith("origin/")]
    return refs


def git_current_branch(repo_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""
    return result.stdout.strip()


def git_has_ref(repo_root: Path, ref_name: str) -> bool:
    result = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", ref_name],
        cwd=repo_root,
        check=False,
    )
    return result.returncode == 0


def choose_default_base_branch(repo_root: Path) -> str:
    remote_branches = git_ref_names(repo_root, "refs/remotes/origin")
    local_branches = git_ref_names(repo_root, "refs/heads")

    for candidate in ("main", "master"):
        if candidate in remote_branches or candidate in local_branches:
            return candidate

    current_branch = git_current_branch(repo_root)
    if current_branch and not current_branch.startswith(FIX_BRANCH_PREFIX):
        return current_branch

    if remote_branches:
        return remote_branches[0]
    if local_branches:
        return local_branches[0]
    return "main"


def resolve_base_branch(repo_root: Path, repo: str, token: str, pr_number: int | None) -> str:
    candidate = os.environ.get("GITHUB_BASE_REF", "").strip() or os.environ.get("GITHUB_REF_NAME", "").strip()
    if not candidate and pr_number is not None:
        pull_request = github_pull_request(repo, token, pr_number)
        candidate = pull_request.get("base", {}).get("ref", "").strip()

    remote_branches = set(git_ref_names(repo_root, "refs/remotes/origin"))
    local_branches = set(git_ref_names(repo_root, "refs/heads"))
    known_branches = remote_branches | local_branches

    if candidate and candidate in known_branches:
        return candidate

    current_branch = git_current_branch(repo_root)
    if current_branch and not current_branch.startswith(FIX_BRANCH_PREFIX) and current_branch in known_branches:
        return current_branch

    return choose_default_base_branch(repo_root)


def resolve_github_repository(repo_root: Path) -> str:
    env_repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    remote_repo = git_origin_repository(repo_root)

    # For local runs, prefer the checked-out git remote over a stale .env value.
    if os.environ.get("GITHUB_ACTIONS", "").strip().lower() != "true" and remote_repo:
        return remote_repo
    if env_repo:
        return env_repo
    if remote_repo:
        return remote_repo
    raise RuntimeError(
        "Unable to determine GitHub repository. Set GITHUB_REPOSITORY=owner/repo "
        "or configure an origin remote that points to GitHub."
    )


def github_changed_files(repo: str, token: str, pr_number: int) -> List[str]:
    owner, name = repo.split("/", 1)
    url = f"https://api.github.com/repos/{owner}/{name}/pulls/{pr_number}/files"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    changed: List[str] = []
    page = 1
    while True:
        response = requests.get(url, headers=headers, params={"page": page, "per_page": 100}, timeout=60)
        response.raise_for_status()
        batch = response.json()
        if not batch:
            break
        changed.extend(normalize_repo_path(item["filename"]) for item in batch)
        page += 1
    return changed


def github_pull_request(repo: str, token: str, pr_number: int) -> Dict[str, Any]:
    owner, name = repo.split("/", 1)
    url = f"https://api.github.com/repos/{owner}/{name}/pulls/{pr_number}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    response = requests.get(url, headers=headers, timeout=60)
    response.raise_for_status()
    return response.json()


def github_find_pull_request(repo: str, token: str, head: str, base: str, state: str = "open") -> Dict[str, Any] | None:
    owner, name = repo.split("/", 1)
    url = f"https://api.github.com/repos/{owner}/{name}/pulls"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    response = requests.get(
        url,
        headers=headers,
        params={"state": state, "head": head, "base": base},
        timeout=60,
    )
    response.raise_for_status()
    pulls = response.json()
    if pulls:
        return pulls[0]
    return None


def compute_exploitability(vuln: Dict[str, Any], guidance: AviatorGuidance, changed_files: Sequence[str]) -> float:
    score = 0.0
    score += min(severity_rank(vuln["severity"]) / 5.0, 1.0) * 0.35

    target_files = {normalize_repo_path(file_change.filename) for file_change in guidance.file_changes}
    if changed_files and target_files & set(changed_files):
        score += 0.20
    elif not changed_files and target_files:
        score += 0.20

    if vuln.get("line"):
        score += 0.10

    confidence = vuln.get("confidence_normalized", "unknown")
    if confidence == "high":
        score += 0.20
    elif confidence == "medium":
        score += 0.10

    if guidance.file_changes:
        score += 0.10

    category = str(vuln.get("category") or "").lower()
    high_signal_categories = (
        "sql injection",
        "command injection",
        "os command",
        "xss",
        "cross-site scripting",
        "deserialization",
        "path manipulation",
        "ssrf",
        "hardcoded",
        "weak cryptographic",
        "nosql injection",
    )
    if any(signal in category for signal in high_signal_categories):
        score += 0.05

    return round(min(score, 1.0), 2)


def quality_gate_check(
    gate: QualityGate,
    vuln: Dict[str, Any],
    guidance: AviatorGuidance | None,
    changed_files: Sequence[str],
) -> Tuple[bool, List[str], float]:
    reasons: List[str] = []

    if severity_rank(vuln["severity"]) < gate.min_severity_rank:
        reasons.append(f"severity gate failed: {vuln['severity']}")

    if gate.require_guidance_available and guidance is None:
        reasons.append("Remediation Guidance is not available")

    if guidance is not None and gate.require_file_changes and not guidance.file_changes:
        reasons.append("no structured FileChanges returned")

    if guidance is not None and not gate.allow_multi_file_changes and len(guidance.file_changes) > 1:
        reasons.append("multi-file changes not allowed by current policy")

    target_files = {normalize_repo_path(file_change.filename) for file_change in guidance.file_changes} if guidance else set()
    if gate.require_changed_file and target_files and not (target_files & set(changed_files)):
        reasons.append("target files not in PR scope")

    exploitability = compute_exploitability(vuln, guidance, changed_files) if guidance else 0.0

    return (len(reasons) == 0, reasons, exploitability)


def resolve_target_path(repo_root: Path, filename: str) -> Path:
    candidate = (repo_root / normalize_repo_path(filename)).resolve()
    candidate.relative_to(repo_root)
    return candidate


def apply_file_remediation(repo_root: Path, file_change: FileRemediation) -> tuple[str, str]:
    full_path = resolve_target_path(repo_root, file_change.filename)
    if not full_path.exists():
        raise PatchApplyError(f"Target file not found: {file_change.filename}")

    before_text = full_path.read_text(encoding="utf-8")
    updated_text = before_text

    for change in file_change.changes:
        if not change.original_code or not change.new_code:
            raise PatchApplyError(
                f"Missing OriginalCode or NewCode for {file_change.filename}:{change.line_from}-{change.line_to}"
            )

        if change.original_code in updated_text:
            updated_text = updated_text.replace(change.original_code, change.new_code, 1)
            continue

        lines = updated_text.splitlines()
        index = max(change.line_from - 1, 0)
        if 0 <= index < len(lines) and lines[index] == change.original_code:
            lines[index] = change.new_code
            updated_text = "\n".join(lines) + ("\n" if updated_text.endswith("\n") else "")
            continue

        if change.context and change.context.value and change.context.value in updated_text:
            patched_context = change.context.value.replace(change.original_code, change.new_code, 1)
            if patched_context != change.context.value:
                updated_text = updated_text.replace(change.context.value, patched_context, 1)
                continue

        raise PatchApplyError(
            f"Unable to safely apply change in {file_change.filename} at lines {change.line_from}-{change.line_to}"
        )

    full_path.write_text(updated_text, encoding="utf-8")
    return before_text, updated_text


def restore_files(repo_root: Path, original_contents: Dict[str, str]) -> None:
    for filename, content in original_contents.items():
        resolve_target_path(repo_root, filename).write_text(content, encoding="utf-8")


def generate_file_diff(before_text: str, after_text: str, filename: str) -> str:
    normalized = normalize_repo_path(filename)
    return "".join(
        difflib.unified_diff(
            before_text.splitlines(keepends=True),
            after_text.splitlines(keepends=True),
            fromfile=f"a/{normalized}",
            tofile=f"b/{normalized}",
        )
    )


def configured_git_identity() -> Tuple[str, str]:
    name = (
        os.environ.get("GIT_USER_NAME")
        or os.environ.get("GIT_AUTHOR_NAME")
        or os.environ.get("GITHUB_ACTOR")
        or "github-actions[bot]"
    ).strip()
    email = (
        os.environ.get("GIT_USER_EMAIL")
        or os.environ.get("GIT_AUTHOR_EMAIL")
        or ""
    ).strip()

    if not email:
        if name == "github-actions[bot]":
            email = "41898282+github-actions[bot]@users.noreply.github.com"
        elif os.environ.get("GITHUB_ACTOR", "").strip():
            email = f"{os.environ['GITHUB_ACTOR'].strip()}@users.noreply.github.com"
        else:
            email = "fortify-aviator@users.noreply.github.com"

    return name, email


def ensure_git_identity(repo_root: Path) -> None:
    name, email = configured_git_identity()
    subprocess.run(["git", "config", "user.name", name], cwd=repo_root, check=True)
    subprocess.run(["git", "config", "user.email", email], cwd=repo_root, check=True)


def git_worktree_start_point(repo_root: Path, base_branch: str) -> str:
    remote_ref = f"refs/remotes/origin/{base_branch}"
    if git_has_ref(repo_root, remote_ref):
        return remote_ref

    local_ref = f"refs/heads/{base_branch}"
    if git_has_ref(repo_root, local_ref):
        return local_ref

    return "HEAD"


@contextmanager
def remediation_worktree(repo_root: Path, base_branch: str, vuln_id: str) -> Iterator[Path]:
    worktree_root = Path(tempfile.mkdtemp(prefix=f"fortify-aviator-{vuln_id}-"))
    start_point = git_worktree_start_point(repo_root, base_branch)
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(worktree_root), start_point],
        cwd=repo_root,
        check=True,
    )
    try:
        yield worktree_root
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(worktree_root)],
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
        )
        shutil.rmtree(worktree_root, ignore_errors=True)


def git_remote_branch_head(repo_root: Path, branch_name: str) -> str:
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--heads", "origin", branch_name],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""

    line = result.stdout.strip()
    if not line:
        return ""
    return line.split()[0]


def create_branch_and_commit(repo_root: Path, branch_name: str, commit_message: str, files: Sequence[str]) -> None:
    remote_head = git_remote_branch_head(repo_root, branch_name)
    subprocess.run(["git", "checkout", "-B", branch_name], cwd=repo_root, check=True)
    ensure_git_identity(repo_root)
    for filename in files:
        subprocess.run(["git", "add", "--", normalize_repo_path(filename)], cwd=repo_root, check=True)
    subprocess.run(["git", "commit", "-m", commit_message], cwd=repo_root, check=True)
    push_command = ["git", "push", "--set-upstream"]
    if remote_head:
        push_command.append(f"--force-with-lease={branch_name}:{remote_head}")
    push_command.extend(["origin", branch_name])
    subprocess.run(push_command, cwd=repo_root, check=True)


def open_pull_request(repo: str, token: str, head: str, base: str, title: str, body: str) -> Dict[str, Any]:
    owner, name = repo.split("/", 1)
    qualified_head = head if ":" in head else f"{owner}:{head}"
    url = f"https://api.github.com/repos/{owner}/{name}/pulls"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    response = requests.post(
        url,
        headers=headers,
        json={"title": title, "head": qualified_head, "base": base, "body": body},
        timeout=60,
    )
    if response.status_code == 404:
        raise requests.HTTPError(
            f"GitHub repository not found or not accessible for PR creation: {repo}. "
            "Verify GITHUB_REPOSITORY, the origin remote, and that GITHUB_TOKEN has repo access.",
            response=response,
        )
    if response.status_code == 403:
        detail = ""
        try:
            payload = response.json()
        except ValueError:
            payload = {}

        message = str(payload.get("message", "")).strip()
        error_messages: List[str] = []
        for error in payload.get("errors", []):
            if isinstance(error, dict):
                error_messages.append(str(error.get("message") or error.get("code") or "").strip())
            else:
                error_messages.append(str(error).strip())
        detail = " | ".join(part for part in [message, *error_messages] if part)

        raise requests.HTTPError(
            "GitHub denied PR creation. If you are using the default GITHUB_TOKEN, verify "
            "the repository setting 'Allow GitHub Actions to create and approve pull requests' "
            "is enabled under Settings > Actions > General, or provide a PAT in the "
            "REMEDIATION_GITHUB_TOKEN secret. "
            f"API response: {detail or 'forbidden'}",
            response=response,
        )
    if response.status_code == 422:
        detail = ""
        try:
            payload = response.json()
        except ValueError:
            payload = {}

        message = str(payload.get("message", "")).strip()
        error_messages: List[str] = []
        for error in payload.get("errors", []):
            if isinstance(error, dict):
                error_messages.append(str(error.get("message") or error.get("code") or "").strip())
            else:
                error_messages.append(str(error).strip())
        detail = " | ".join(part for part in [message, *error_messages] if part)

        if "A pull request already exists for" in detail:
            existing_pull = github_find_pull_request(repo, token, qualified_head, base, state="open")
            if existing_pull is not None:
                existing_pull["_existing"] = True
                return existing_pull

        raise requests.HTTPError(
            f"GitHub rejected PR creation for {qualified_head} -> {base}: {detail or 'unprocessable entity'}",
            response=response,
        )
    response.raise_for_status()
    return response.json()


def remediation_body(vuln: Dict[str, Any], guidance: AviatorGuidance, exploitability: float, diffs: List[str]) -> str:
    combined_diff = "\n".join(diffs)[:50000]
    updated_files = "\n".join(f"- {normalize_repo_path(file_change.filename)}" for file_change in guidance.file_changes)
    return f"""## Automated Fortify Aviator remediation PR

**Finding**
- Vulnerability Id: {vuln['vuln_id']}
- Category: {vuln['category']}
- Severity: {vuln['severity']}
- Confidence: {vuln['confidence']}
- File: {vuln['file_path']}:{vuln['line']}
- Exploitability score: {exploitability}

**Aviator analysis**
{guidance.audit_comment}

**Updated files**
{updated_files}

**Traceability**
- Aviator instanceId: {guidance.instance_id}
- Guidance writeDate: {guidance.write_date}

**Generated patch**
```diff
{combined_diff}
```
"""


def comment_only_summary(vuln: Dict[str, Any], reasons: List[str]) -> Dict[str, Any]:
    return {
        "vulnerability": vuln.get("vuln_id"),
        "status": "comment_only_or_skipped",
        "reasons": reasons,
    }


def error_summary(vuln: Dict[str, Any], error: Exception) -> Dict[str, Any]:
    return {
        "vulnerability": vuln.get("vuln_id"),
        "status": "error",
        "error": str(error),
    }


def run() -> None:
    load_local_env_file()
    repo_root = Path(os.environ.get("GITHUB_WORKSPACE") or Path(__file__).resolve().parents[2]).resolve()
    repo = resolve_github_repository(repo_root)
    token = os.environ["GITHUB_TOKEN"]
    pr_number_raw = os.environ.get("PR_NUMBER", "").strip()
    pr_number = int(pr_number_raw) if pr_number_raw else None
    base_branch = resolve_base_branch(repo_root, repo, token, pr_number)

    client = FoDAviatorClient.from_env()
    severity_strings = configured_severity_strings()
    raw_vulns = client.iter_vulnerabilities(
        fortify_aviator=True,
        severity_strings=severity_strings,
    )
    changed_files = github_changed_files(repo, token, pr_number) if pr_number is not None else []
    gate = QualityGate(require_changed_file=bool(changed_files))

    decisions: List[Dict[str, Any]] = []

    for raw_vuln in raw_vulns:
        vuln = client.normalize_vulnerability(raw_vuln)
        if not vuln["vuln_id"]:
            continue

        guidance_payload = client.get_aviator_guidance(int(vuln["vuln_id"]))
        guidance = client.parse_aviator_guidance(guidance_payload)
        passed, reasons, exploitability = quality_gate_check(gate, vuln, guidance, changed_files)

        if not guidance:
            decisions.append(comment_only_summary(vuln, reasons or ["Remediation Guidance is not available"]))
            continue

        if not passed:
            decisions.append(comment_only_summary(vuln, reasons))
            continue

        branch_name = f"fortify-aviator-fix-{vuln['vuln_id']}"
        commit_message = f"fix: Fortify Aviator remediation for vulnerability {vuln['vuln_id']}"
        try:
            with remediation_worktree(repo_root, base_branch, str(vuln["vuln_id"])) as worktree_root:
                all_diffs: List[str] = []
                applied_files: List[str] = []

                for file_change in guidance.file_changes:
                    before_text, after_text = apply_file_remediation(worktree_root, file_change)
                    diff_text = generate_file_diff(before_text, after_text, file_change.filename)
                    if not diff_text.strip():
                        raise PatchApplyError(f"No diff produced for {file_change.filename}")
                    all_diffs.append(diff_text)
                    applied_files.append(file_change.filename)

                create_branch_and_commit(worktree_root, branch_name, commit_message, applied_files)

            pull_request = open_pull_request(
                repo=repo,
                token=token,
                head=branch_name,
                base=base_branch,
                title=f"[AUTO] Fortify Aviator fix for {vuln['category']}",
                body=remediation_body(vuln, guidance, exploitability, all_diffs),
            )
            decisions.append(
                {
                    "status": "pr_already_exists" if pull_request.get("_existing") else "pr_created",
                    "vulnerability": vuln["vuln_id"],
                    "files": [normalize_repo_path(filename) for filename in applied_files],
                    "exploitability": exploitability,
                    "pull_request": pull_request.get("html_url"),
                }
            )
        except PatchApplyError as exc:
            decisions.append(comment_only_summary(vuln, [str(exc)]))
            continue
        except (requests.HTTPError, subprocess.CalledProcessError, RuntimeError) as exc:
            decisions.append(error_summary(vuln, exc))
            continue

    print(json.dumps({"results": decisions or [{"status": "no eligible remediation candidate found"}]}, indent=2))


if __name__ == "__main__":
    run()
