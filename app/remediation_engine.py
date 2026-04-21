from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Sequence, Tuple

import requests

from fod_aviator import AviatorGuidance, FileRemediation, FoDAviatorClient, normalize_severity_label, severity_rank
from metrics import (
    publish_remediation_metrics_markdown,
    render_remediation_metrics_markdown,
    render_result_summary_markdown,
    synthesize_result_summary,
    summarize_remediation_outcomes,
    synthesize_remediation_metrics,
)


class PatchApplyError(Exception):
    pass


@dataclass
class QualityGate:
    min_severity_rank: int = 4
    require_guidance_available: bool = True
    require_file_changes: bool = True
    require_changed_file: bool = True
    allow_multi_file_changes: bool = True
    allowed_severities: Tuple[str, ...] = ()


VALID_SEVERITY_STRINGS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}
VALID_PR_GROUPING_MODES = {"issue", "category"}
FIX_BRANCH_PREFIX = "fortify-aviator-fix-"
GITHUB_PR_BODY_MAX_CHARS = 65536


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


def configured_allowed_severities(severity_strings: Sequence[str]) -> Tuple[str, ...]:
    allowed = []
    for severity in severity_strings:
        normalized = normalize_severity_label(severity).lower()
        if normalized and normalized not in allowed:
            allowed.append(normalized)
    return tuple(allowed)


def configured_pr_grouping_mode() -> str:
    raw_value = os.environ.get("FOD_PR_GROUPING", "category").strip().lower()
    if raw_value not in VALID_PR_GROUPING_MODES:
        allowed = ", ".join(sorted(VALID_PR_GROUPING_MODES))
        raise RuntimeError(f"Unsupported FOD_PR_GROUPING value: {raw_value}. Allowed values: {allowed}")
    return raw_value


def persist_results_payload(payload: Dict[str, Any]) -> None:
    results_path = os.environ.get("REMEDIATION_RESULTS_PATH", "").strip()
    rendered = json.dumps(payload, indent=2)
    if results_path:
        target_path = Path(results_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


def normalize_repo_path(value: str) -> str:
    return Path(value).as_posix().lstrip("./")


def remediation_group_key(vuln: Dict[str, Any]) -> Tuple[str, str]:
    severity = str(vuln.get("severity") or "Unknown").strip() or "Unknown"
    category = str(vuln.get("category") or "Uncategorized").strip() or "Uncategorized"
    return severity, category


def remediation_batch_key(vuln: Dict[str, Any], grouping_mode: str) -> Tuple[str, str, str]:
    severity, category = remediation_group_key(vuln)
    if grouping_mode == "category":
        return severity, category, "category"
    return severity, category, str(vuln.get("vuln_id") or "unknown")


def slugify_branch_component(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "group"


def remediation_group_branch_name(severity: str, category: str) -> str:
    severity_slug = slugify_branch_component(severity)
    category_slug = slugify_branch_component(category)
    base = f"{FIX_BRANCH_PREFIX}{severity_slug}-{category_slug}"
    if len(base) <= 120:
        return base

    digest = hashlib.sha1(f"{severity}|{category}".encode("utf-8")).hexdigest()[:12]
    trimmed = base[: 120 - len(digest) - 1].rstrip("-")
    return f"{trimmed}-{digest}"


def remediation_group_title(severity: str, category: str) -> str:
    return f"[AUTO] Fortify Aviator fixes for {severity} - {category}"


def remediation_issue_branch_name(vuln: Dict[str, Any]) -> str:
    return f"{FIX_BRANCH_PREFIX}{vuln['vuln_id']}"


def remediation_issue_title(vuln: Dict[str, Any]) -> str:
    return f"[AUTO] Fortify Aviator fix for {vuln['category']} ({vuln['vuln_id']})"


def remediation_batch_branch_name(vulns: Sequence[Dict[str, Any]], grouping_mode: str) -> str:
    if not vulns:
        raise RuntimeError("Cannot build remediation branch name without vulnerabilities")
    if grouping_mode == "category":
        severity, category = remediation_group_key(vulns[0])
        return remediation_group_branch_name(severity, category)
    return remediation_issue_branch_name(vulns[0])


def remediation_batch_title(vulns: Sequence[Dict[str, Any]], grouping_mode: str) -> str:
    if not vulns:
        raise RuntimeError("Cannot build remediation title without vulnerabilities")
    if grouping_mode == "category":
        severity, category = remediation_group_key(vulns[0])
        return remediation_group_title(severity, category)
    return remediation_issue_title(vulns[0])


def remediation_batch_worktree_name(vulns: Sequence[Dict[str, Any]], grouping_mode: str) -> str:
    if not vulns:
        raise RuntimeError("Cannot build remediation worktree name without vulnerabilities")
    if grouping_mode == "category":
        severity, category = remediation_group_key(vulns[0])
        return f"{severity}-{category}"
    return str(vulns[0]["vuln_id"])


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


def github_update_pull_request(repo: str, token: str, pr_number: int, title: str, body: str) -> Dict[str, Any]:
    owner, name = repo.split("/", 1)
    url = f"https://api.github.com/repos/{owner}/{name}/pulls/{pr_number}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    response = requests.patch(
        url,
        headers=headers,
        json={"title": title, "body": body},
        timeout=60,
    )
    response.raise_for_status()
    return response.json()


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

    confidence = remediation_confidence(vuln, guidance)
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


def remediation_confidence(vuln: Dict[str, Any], guidance: AviatorGuidance | None) -> str:
    confidence = vuln.get("confidence_normalized", "unknown")
    if confidence == "pending_review" and guidance is not None and guidance.file_changes:
        return "medium"
    return confidence


def quality_gate_check(
    gate: QualityGate,
    vuln: Dict[str, Any],
    guidance: AviatorGuidance | None,
    changed_files: Sequence[str],
) -> Tuple[bool, List[str], float]:
    reasons: List[str] = []
    confidence = remediation_confidence(vuln, guidance)
    auditor_status = vuln.get("auditor_status", "Unknown")
    normalized_severity = normalize_severity_label(vuln.get("severity") or "Unknown").lower()

    if gate.allowed_severities and normalized_severity not in gate.allowed_severities:
        reasons.append(f"severity not in configured FOD_SEVERITY_STRINGS: {vuln['severity']}")

    if severity_rank(vuln["severity"]) < gate.min_severity_rank:
        reasons.append(f"severity gate failed: {vuln['severity']}")

    if confidence == "false_positive":
        reasons.append(f"auditor status indicates false positive: {auditor_status}")

    if confidence == "manual_intervention":
        reasons.append(f"auditor status requires manual intervention: {auditor_status}")

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


def git_diff_for_files(repo_root: Path, files: Sequence[str]) -> List[str]:
    normalized_files = sorted({normalize_repo_path(filename) for filename in files if filename})
    if not normalized_files:
        return []

    result = subprocess.run(
        ["git", "diff", "--", *normalized_files],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return [result.stdout] if result.stdout.strip() else []


def configured_validation_command() -> str:
    return os.environ.get("REMEDIATION_VALIDATE_COMMAND", "").strip()


def should_validate_remediation(files: Sequence[str]) -> bool:
    if not files:
        return False
    command = configured_validation_command().lower()
    return command not in {"", "0", "false", "off", "none"}


def validate_remediation_changes(repo_root: Path, files: Sequence[str]) -> None:
    if not should_validate_remediation(files):
        return

    command = configured_validation_command()

    result = subprocess.run(
        shlex.split(command),
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return

    output = "\n".join(part.strip() for part in [result.stdout, result.stderr] if part.strip())
    detail = truncate_text(output, 4000, "validation output") if output else "No validation output captured."
    raise RuntimeError(f"Validation command failed for remediation changes ({command}).\n{detail}")


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


def truncate_text(text: str, max_chars: int, label: str) -> str:
    value = str(text or "")
    if len(value) <= max_chars:
        return value

    suffix = f"\n...(truncated {label}; {len(value) - max_chars} characters omitted)"
    keep = max(max_chars - len(suffix), 0)
    return value[:keep].rstrip() + suffix


def summarize_bulleted_lines(lines: Sequence[str], limit: int, omitted_label: str) -> str:
    if not lines:
        return "- None"

    visible = list(lines[:limit])
    omitted = len(lines) - len(visible)
    if omitted > 0:
        visible.append(f"- ... {omitted} additional {omitted_label} omitted")
    return "\n".join(visible)


def build_grouped_analysis_sections(
    vulns: Sequence[Dict[str, Any]],
    guidance_by_vuln_id: Dict[str, AviatorGuidance],
    exploitability_by_vuln_id: Dict[str, float],
    max_entries: int,
    max_comment_chars: int,
) -> str:
    sections: List[str] = []
    for vuln in vulns[:max_entries]:
        vuln_id = str(vuln["vuln_id"])
        comment = guidance_by_vuln_id[vuln_id].audit_comment or "(No audit comment provided)"
        comment = truncate_text(comment, max_comment_chars, "analysis comment")
        sections.append(
            "\n".join(
                [
                    f"### Vulnerability {vuln_id}",
                    f"- File: {normalize_repo_path(str(vuln.get('file_path') or '(not set)'))}:{vuln.get('line') or 0}",
                    f"- Exploitability: {exploitability_by_vuln_id[vuln_id]}",
                    "",
                    comment,
                ]
            )
        )

    omitted = len(vulns) - min(len(vulns), max_entries)
    if omitted > 0:
        sections.append(
            f"### Additional vulnerabilities\n{omitted} additional vulnerability analyses were omitted to keep the PR body within GitHub limits."
        )
    return "\n\n".join(sections)


def render_grouped_remediation_body(
    vulns: Sequence[Dict[str, Any]],
    guidance_by_vuln_id: Dict[str, AviatorGuidance],
    exploitability_by_vuln_id: Dict[str, float],
    diffs: List[str],
    skipped_vulns: Sequence[Dict[str, str]],
    grouping_mode: str,
    *,
    max_finding_lines: int,
    max_updated_files: int,
    max_traceability_lines: int,
    max_skipped_lines: int,
    max_analysis_entries: int,
    max_analysis_chars: int,
    max_diff_chars: int,
) -> str:
    severity, category = remediation_group_key(vulns[0])
    is_category_group = grouping_mode == "category"
    scope_heading = "Group" if is_category_group else "Issue"
    scope_count_label = "Included vulnerabilities" if is_category_group else "Vulnerability ID"
    scope_count_value = str(len(vulns)) if is_category_group else str(vulns[0]["vuln_id"])
    skipped_heading = (
        "Skipped Vulnerabilities In This Group"
        if is_category_group
        else "Skipped Findings While Preparing This PR"
    )
    updated_files = sorted(
        {
            normalize_repo_path(file_change.filename)
            for vuln in vulns
            for file_change in guidance_by_vuln_id[str(vuln["vuln_id"])].file_changes
        }
    )
    finding_lines = summarize_bulleted_lines(
        [
            (
                f"- {vuln['vuln_id']} | {normalize_repo_path(str(vuln.get('file_path') or '(not set)'))}:"
                f"{vuln.get('line') or 0} | confidence={vuln['confidence']} | "
                f"exploitability={exploitability_by_vuln_id[str(vuln['vuln_id'])]}"
            )
            for vuln in vulns
        ],
        max_finding_lines,
        "findings",
    )
    analysis_sections = build_grouped_analysis_sections(
        vulns,
        guidance_by_vuln_id,
        exploitability_by_vuln_id,
        max_entries=max_analysis_entries,
        max_comment_chars=max_analysis_chars,
    )
    traceability_lines = summarize_bulleted_lines(
        [
            (
                f"- {vuln['vuln_id']} | instanceId="
                f"{guidance_by_vuln_id[str(vuln['vuln_id'])].instance_id or '(not set)'} | writeDate="
                f"{guidance_by_vuln_id[str(vuln['vuln_id'])].write_date or '(not set)'}"
            )
            for vuln in vulns
        ],
        max_traceability_lines,
        "traceability entries",
    )
    skipped_section = ""
    if skipped_vulns:
        skipped_lines = summarize_bulleted_lines(
            [
                f"- {item['vulnerability']}: {item['reason']}"
                for item in skipped_vulns
            ],
            max_skipped_lines,
            "skipped vulnerabilities",
        )
        skipped_section = f"""
**{skipped_heading}**
{skipped_lines}
"""

    updated_file_lines = summarize_bulleted_lines(
        [f"- {filename}" for filename in updated_files],
        max_updated_files,
        "updated files",
    )
    combined_diff = truncate_text("\n".join(diffs), max_diff_chars, "generated patch preview")

    return f"""## Automated Fortify Aviator remediation PR

**{scope_heading}**
- Severity: {severity}
- Category: {category}
- {scope_count_label}: {scope_count_value}

**Findings**
{finding_lines}

**Aviator analysis**
{analysis_sections}

**Updated files**
{updated_file_lines}

**Traceability**
{traceability_lines}
{skipped_section}

**Generated patch**
```diff
{combined_diff}
```
"""


def grouped_remediation_body(
    vulns: Sequence[Dict[str, Any]],
    guidance_by_vuln_id: Dict[str, AviatorGuidance],
    exploitability_by_vuln_id: Dict[str, float],
    diffs: List[str],
    skipped_vulns: Sequence[Dict[str, str]],
    grouping_mode: str,
) -> str:
    if not vulns:
        raise RuntimeError("Cannot build remediation body without vulnerabilities")

    variants = (
        {
            "max_finding_lines": 40,
            "max_updated_files": 60,
            "max_traceability_lines": 40,
            "max_skipped_lines": 40,
            "max_analysis_entries": 12,
            "max_analysis_chars": 1500,
            "max_diff_chars": 20000,
        },
        {
            "max_finding_lines": 20,
            "max_updated_files": 30,
            "max_traceability_lines": 20,
            "max_skipped_lines": 20,
            "max_analysis_entries": 6,
            "max_analysis_chars": 800,
            "max_diff_chars": 10000,
        },
        {
            "max_finding_lines": 10,
            "max_updated_files": 20,
            "max_traceability_lines": 10,
            "max_skipped_lines": 10,
            "max_analysis_entries": 3,
            "max_analysis_chars": 400,
            "max_diff_chars": 4000,
        },
    )

    for variant in variants:
        body = render_grouped_remediation_body(
            vulns,
            guidance_by_vuln_id,
            exploitability_by_vuln_id,
            diffs,
            skipped_vulns,
            grouping_mode,
            **variant,
        )
        if len(body) <= GITHUB_PR_BODY_MAX_CHARS:
            return body

    severity, category = remediation_group_key(vulns[0])
    is_category_group = grouping_mode == "category"
    scope_heading = "Group" if is_category_group else "Issue"
    scope_count_label = "Included vulnerabilities" if is_category_group else "Vulnerability ID"
    scope_count_value = str(len(vulns)) if is_category_group else str(vulns[0]["vuln_id"])
    included_ids_heading = "Included vulnerability ids" if is_category_group else "Vulnerability id"
    skipped_heading = (
        "Skipped Vulnerabilities In This Group"
        if is_category_group
        else "Skipped Findings While Preparing This PR"
    )
    included_ids = ", ".join(str(vuln["vuln_id"]) for vuln in vulns[:20])
    if len(vulns) > 20:
        included_ids = f"{included_ids}, ... (+{len(vulns) - 20} more)"
    skipped_lines = summarize_bulleted_lines(
        [f"- {item['vulnerability']}: {item['reason']}" for item in skipped_vulns],
        10,
        "skipped vulnerabilities",
    )
    files_preview = summarize_bulleted_lines(
        sorted(
            {
                f"- {normalize_repo_path(file_change.filename)}"
                for guidance in guidance_by_vuln_id.values()
                for file_change in guidance.file_changes
            }
        ),
        20,
        "updated files",
    )
    return f"""## Automated Fortify Aviator remediation PR

**{scope_heading}**
- Severity: {severity}
- Category: {category}
- {scope_count_label}: {scope_count_value}

**{included_ids_heading}**
{included_ids}

**Updated files**
{files_preview}

**{skipped_heading}**
{skipped_lines}

The full generated patch was omitted from the PR body to satisfy GitHub's maximum body length limit. Review the branch diff in the PR Files changed tab for the complete remediation patch.
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


def classify_skip_outcome(reasons: Sequence[str], guidance: AviatorGuidance | None) -> str:
    lowered_reasons = [str(reason).strip().lower() for reason in reasons]

    if any("false positive" in reason for reason in lowered_reasons):
        return "false_positive"
    if any("manual intervention" in reason for reason in lowered_reasons):
        return "manual_intervention"
    if guidance is None or any("guidance is not available" in reason for reason in lowered_reasons):
        return "no_fix_suggestion"
    if any("no structured filechanges returned" in reason for reason in lowered_reasons):
        return "no_fix_suggestion"
    if any("severity gate failed" in reason for reason in lowered_reasons):
        return "severity_filtered_out"
    if any("severity not in configured fod_severity_strings" in reason for reason in lowered_reasons):
        return "severity_filtered_out"
    if any("target files not in pr scope" in reason for reason in lowered_reasons):
        return "out_of_scope"
    if any("multi-file changes not allowed" in reason for reason in lowered_reasons):
        return "policy_skipped"
    return "other_skipped"


def run() -> None:
    load_local_env_file()
    repo_root = Path(os.environ.get("GITHUB_WORKSPACE") or Path(__file__).resolve().parents[2]).resolve()
    repo = resolve_github_repository(repo_root)
    token = os.environ["GITHUB_TOKEN"]
    pr_number_raw = os.environ.get("PR_NUMBER", "").strip()
    pr_number = int(pr_number_raw) if pr_number_raw else None
    base_branch = resolve_base_branch(repo_root, repo, token, pr_number)

    client = FoDAviatorClient.from_env()
    raw_severity_strings = os.environ.get("FOD_SEVERITY_STRINGS")
    severity_strings = configured_severity_strings()
    allowed_severities = configured_allowed_severities(severity_strings)
    min_severity_rank = min((severity_rank(severity) for severity in severity_strings), default=0)
    pr_grouping_mode = configured_pr_grouping_mode()
    severity_source = "env" if raw_severity_strings is not None else "default"
    raw_severity_display = raw_severity_strings if raw_severity_strings is not None else "Critical"
    normalized_severity_display = ",".join(severity_strings) if severity_strings else "(none)"
    print(
        f"Effective FOD_SEVERITY_STRINGS ({severity_source}): "
        f"raw='{raw_severity_display}' normalized='{normalized_severity_display}'"
    )
    print(f"Effective FOD_PR_GROUPING: {pr_grouping_mode}")
    raw_vulns = client.iter_vulnerabilities(
        fortify_aviator=True,
        severity_strings=severity_strings,
    )
    changed_files = github_changed_files(repo, token, pr_number) if pr_number is not None else []
    gate = QualityGate(
        min_severity_rank=min_severity_rank,
        require_changed_file=bool(changed_files),
        allowed_severities=allowed_severities,
    )

    decisions: List[Dict[str, Any]] = []
    grouped_candidates: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    metrics_records: Dict[str, Dict[str, Any]] = {}

    for raw_vuln in raw_vulns:
        vuln = client.normalize_vulnerability(raw_vuln)
        if not vuln["vuln_id"]:
            continue

        vuln_id = str(vuln["vuln_id"])
        normalized_vuln_severity = normalize_severity_label(vuln.get("severity") or "Unknown").lower()
        if gate.allowed_severities and normalized_vuln_severity not in gate.allowed_severities:
            decisions.append(
                comment_only_summary(
                    vuln,
                    [f"severity not in configured FOD_SEVERITY_STRINGS: {vuln['severity']}"],
                )
            )
            metrics_records[vuln_id] = {
                "vulnerability": vuln_id,
                "severity": str(vuln.get("severity") or "Unknown"),
                "category": str(vuln.get("category") or "Uncategorized"),
                "auditor_status": str(vuln.get("auditor_status") or "Unknown"),
                "guidance_available": False,
                "structured_fix_available": False,
                "eligible": False,
                "outcome": "severity_filtered_out",
                "detail": f"severity not in configured FOD_SEVERITY_STRINGS: {vuln['severity']}",
            }
            continue

        guidance_payload = client.get_aviator_guidance(int(vuln["vuln_id"]))
        guidance = client.parse_aviator_guidance(guidance_payload)
        passed, reasons, exploitability = quality_gate_check(gate, vuln, guidance, changed_files)
        metrics_records[vuln_id] = {
            "vulnerability": vuln_id,
            "severity": str(vuln.get("severity") or "Unknown"),
            "category": str(vuln.get("category") or "Uncategorized"),
            "auditor_status": str(vuln.get("auditor_status") or "Unknown"),
            "guidance_available": guidance is not None,
            "structured_fix_available": bool(guidance and guidance.file_changes),
            "eligible": False,
            "outcome": "",
            "detail": "",
        }

        if not guidance:
            metrics_records[vuln_id]["outcome"] = "no_fix_suggestion"
            metrics_records[vuln_id]["detail"] = "Remediation Guidance is not available"
            decisions.append(comment_only_summary(vuln, reasons or ["Remediation Guidance is not available"]))
            continue

        if not passed:
            metrics_records[vuln_id]["outcome"] = classify_skip_outcome(reasons, guidance)
            metrics_records[vuln_id]["detail"] = "; ".join(reasons)
            decisions.append(comment_only_summary(vuln, reasons))
            continue

        metrics_records[vuln_id]["eligible"] = True
        metrics_records[vuln_id]["outcome"] = "eligible"
        grouped_candidates.setdefault(remediation_batch_key(vuln, pr_grouping_mode), []).append(
            {
                "vuln": vuln,
                "guidance": guidance,
                "exploitability": exploitability,
            }
        )

    for _, candidates in grouped_candidates.items():
        batch_vulns = [candidate["vuln"] for candidate in candidates]
        severity, category = remediation_group_key(batch_vulns[0])
        branch_name = remediation_batch_branch_name(batch_vulns, pr_grouping_mode)
        title = remediation_batch_title(batch_vulns, pr_grouping_mode)
        if pr_grouping_mode == "category":
            commit_message = f"fix: Fortify Aviator remediations for {severity} {category}"
        else:
            commit_message = f"fix: Fortify Aviator remediation for vulnerability {batch_vulns[0]['vuln_id']}"
        included_vulns: List[Dict[str, Any]] = []
        guidance_by_vuln_id: Dict[str, AviatorGuidance] = {}
        exploitability_by_vuln_id: Dict[str, float] = {}
        skipped_vulns: List[Dict[str, str]] = []

        try:
            with remediation_worktree(
                repo_root,
                base_branch,
                remediation_batch_worktree_name(batch_vulns, pr_grouping_mode),
            ) as worktree_root:
                applied_files: List[str] = []

                for candidate in candidates:
                    vuln = candidate["vuln"]
                    guidance = candidate["guidance"]
                    exploitability = candidate["exploitability"]
                    vuln_id = str(vuln["vuln_id"])
                    vuln_original_contents: Dict[str, str] = {}
                    vuln_applied_files: List[str] = []

                    try:
                        for file_change in guidance.file_changes:
                            filename = file_change.filename
                            if filename not in vuln_original_contents:
                                vuln_original_contents[filename] = resolve_target_path(
                                    worktree_root, filename
                                ).read_text(encoding="utf-8")

                            before_text, after_text = apply_file_remediation(worktree_root, file_change)
                            diff_text = generate_file_diff(before_text, after_text, file_change.filename)
                            if not diff_text.strip():
                                raise PatchApplyError(f"No diff produced for {file_change.filename}")
                            vuln_applied_files.append(filename)
                    except PatchApplyError as exc:
                        restore_files(worktree_root, vuln_original_contents)
                        reason = truncate_text(" ".join(str(exc).split()), 600, "skip reason")
                        metrics_records[vuln_id]["outcome"] = "patch_apply_failure"
                        metrics_records[vuln_id]["detail"] = str(exc)
                        skipped_vulns.append(
                            {
                                "vulnerability": vuln_id,
                                "reason": reason,
                            }
                        )
                        continue

                    if pr_grouping_mode == "category":
                        candidate_validation_files = sorted(
                            {
                                normalize_repo_path(filename)
                                for filename in [*applied_files, *vuln_applied_files]
                            }
                        )
                        try:
                            validate_remediation_changes(worktree_root, candidate_validation_files)
                        except RuntimeError as exc:
                            restore_files(worktree_root, vuln_original_contents)
                            reason = truncate_text(" ".join(str(exc).split()), 600, "skip reason")
                            metrics_records[vuln_id]["outcome"] = "validation_failure"
                            metrics_records[vuln_id]["detail"] = str(exc)
                            skipped_vulns.append(
                                {
                                    "vulnerability": vuln_id,
                                    "reason": reason,
                                }
                            )
                            continue

                    included_vulns.append(vuln)
                    guidance_by_vuln_id[vuln_id] = guidance
                    exploitability_by_vuln_id[vuln_id] = exploitability
                    applied_files.extend(vuln_applied_files)

                unique_applied_files = sorted({normalize_repo_path(filename) for filename in applied_files})
                if not included_vulns or not unique_applied_files:
                    if skipped_vulns:
                        for skipped in skipped_vulns:
                            decisions.append(
                                comment_only_summary(
                                    {"vuln_id": skipped["vulnerability"]},
                                    [skipped["reason"]],
                                )
                            )
                    continue

                all_diffs = git_diff_for_files(worktree_root, unique_applied_files)
                if not all_diffs:
                    raise RuntimeError(f"No remediation diff produced for {severity} / {category}")

                validate_remediation_changes(worktree_root, unique_applied_files)
                create_branch_and_commit(worktree_root, branch_name, commit_message, unique_applied_files)

            body = grouped_remediation_body(
                included_vulns,
                guidance_by_vuln_id,
                exploitability_by_vuln_id,
                all_diffs,
                skipped_vulns,
                pr_grouping_mode,
            )
            pull_request = open_pull_request(
                repo=repo,
                token=token,
                head=branch_name,
                base=base_branch,
                title=title,
                body=body,
            )
            if pull_request.get("_existing"):
                pull_request = github_update_pull_request(repo, token, int(pull_request["number"]), title, body)
                pull_request["_existing"] = True
            for vuln in included_vulns:
                metrics_records[str(vuln["vuln_id"])]["outcome"] = "autofix_applied"
                metrics_records[str(vuln["vuln_id"])]["detail"] = pull_request.get("html_url", "")
            decisions.append(
                {
                    "status": "pr_already_exists" if pull_request.get("_existing") else "pr_created",
                    "severity": severity,
                    "category": category,
                    "vulnerabilities": [vuln["vuln_id"] for vuln in included_vulns],
                    "skipped_vulnerabilities": skipped_vulns,
                    "files": sorted(
                        {
                            normalize_repo_path(file_change.filename)
                            for guidance in guidance_by_vuln_id.values()
                            for file_change in guidance.file_changes
                        }
                    ),
                    "pull_request": pull_request.get("html_url"),
                }
            )
        except (requests.HTTPError, subprocess.CalledProcessError, RuntimeError) as exc:
            decisions.append(
                {
                    "severity": severity,
                    "category": category,
                    "vulnerabilities": [
                        vuln["vuln_id"] for vuln in included_vulns
                    ] if included_vulns else [candidate["vuln"]["vuln_id"] for candidate in candidates],
                    "skipped_vulnerabilities": skipped_vulns,
                    "status": "error",
                    "error": str(exc),
                }
            )
            for candidate in candidates:
                vuln_id = str(candidate["vuln"]["vuln_id"])
                if metrics_records.get(vuln_id, {}).get("outcome") in {
                    "patch_apply_failure",
                    "validation_failure",
                    "autofix_applied",
                }:
                    continue
                metrics_records[vuln_id]["outcome"] = "fix_failure"
                metrics_records[vuln_id]["detail"] = str(exc)
            continue

    metrics = summarize_remediation_outcomes(metrics_records.values(), decisions)
    metrics_summary = synthesize_remediation_metrics(metrics)
    metrics_markdown = render_remediation_metrics_markdown(metrics)
    results_summary = synthesize_result_summary(metrics_records.values(), decisions)
    results_markdown = render_result_summary_markdown(results_summary)
    summary_path = publish_remediation_metrics_markdown(f"{metrics_markdown}\n{results_markdown}")
    persist_results_payload(
        {
            "metrics": metrics,
            "metrics_summary": metrics_summary,
            "results_summary": results_summary,
            "metrics_published_to": summary_path or None,
            "results_count": len(decisions),
        }
    )


if __name__ == "__main__":
    run()
