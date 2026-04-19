from __future__ import annotations

import difflib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import requests

from fod_aviator import AviatorGuidance, FileRemediation, FoDAviatorClient, severity_rank


class PatchApplyError(Exception):
    pass


@dataclass
class QualityGate:
    min_severity_rank: int = 4
    allowed_confidence: Tuple[str, ...] = ("high",)
    require_guidance_available: bool = True
    require_file_changes: bool = True
    require_changed_file: bool = True
    min_exploitability_score: float = 0.70
    allow_multi_file_changes: bool = True


def normalize_repo_path(value: str) -> str:
    return Path(value).as_posix().lstrip("./")


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

    confidence = vuln.get("confidence_normalized", "unknown")
    if confidence not in gate.allowed_confidence:
        reasons.append(f"confidence gate failed: {confidence}")

    if gate.require_guidance_available and guidance is None:
        reasons.append("guidance unavailable")

    if guidance is not None and gate.require_file_changes and not guidance.file_changes:
        reasons.append("no structured FileChanges returned")

    if guidance is not None and not gate.allow_multi_file_changes and len(guidance.file_changes) > 1:
        reasons.append("multi-file changes not allowed by current policy")

    target_files = {normalize_repo_path(file_change.filename) for file_change in guidance.file_changes} if guidance else set()
    if gate.require_changed_file and target_files and not (target_files & set(changed_files)):
        reasons.append("target files not in PR scope")

    exploitability = compute_exploitability(vuln, guidance, changed_files) if guidance else 0.0
    if exploitability < gate.min_exploitability_score:
        reasons.append(f"exploitability gate failed: {exploitability}")

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


def create_branch_and_commit(repo_root: Path, branch_name: str, commit_message: str, files: Sequence[str]) -> None:
    subprocess.run(["git", "checkout", "-b", branch_name], cwd=repo_root, check=True)
    for filename in files:
        subprocess.run(["git", "add", "--", normalize_repo_path(filename)], cwd=repo_root, check=True)
    subprocess.run(["git", "commit", "-m", commit_message], cwd=repo_root, check=True)
    subprocess.run(["git", "push", "--set-upstream", "origin", branch_name], cwd=repo_root, check=True)


def open_pull_request(repo: str, token: str, head: str, base: str, title: str, body: str) -> Dict[str, Any]:
    owner, name = repo.split("/", 1)
    url = f"https://api.github.com/repos/{owner}/{name}/pulls"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    response = requests.post(
        url,
        headers=headers,
        json={"title": title, "head": head, "base": base, "body": body},
        timeout=60,
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


def run() -> None:
    repo_root = Path(os.environ.get("GITHUB_WORKSPACE") or Path(__file__).resolve().parents[2]).resolve()
    repo = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GITHUB_TOKEN"]
    pr_number_raw = os.environ.get("PR_NUMBER", "").strip()
    pr_number = int(pr_number_raw) if pr_number_raw else None
    base_branch = os.environ.get("GITHUB_BASE_REF", "").strip() or os.environ.get("GITHUB_REF_NAME", "").strip()
    if not base_branch and pr_number is not None:
        pull_request = github_pull_request(repo, token, pr_number)
        base_branch = pull_request.get("base", {}).get("ref") or "master"
    elif not base_branch:
        base_branch = "master"

    client = FoDAviatorClient.from_env()
    raw_vulns = client.list_vulnerabilities(only_guidance_available=True).get("items", [])
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
            decisions.append(comment_only_summary(vuln, reasons or ["guidance unavailable"]))
            continue

        if not passed:
            decisions.append(comment_only_summary(vuln, reasons))
            continue

        all_diffs: List[str] = []
        applied_files: List[str] = []
        original_contents: Dict[str, str] = {}

        try:
            for file_change in guidance.file_changes:
                before_text, after_text = apply_file_remediation(repo_root, file_change)
                original_contents[file_change.filename] = before_text
                diff_text = generate_file_diff(before_text, after_text, file_change.filename)
                if not diff_text.strip():
                    raise PatchApplyError(f"No diff produced for {file_change.filename}")
                all_diffs.append(diff_text)
                applied_files.append(file_change.filename)
        except PatchApplyError as exc:
            restore_files(repo_root, original_contents)
            decisions.append(comment_only_summary(vuln, [str(exc)]))
            continue

        branch_name = f"fortify-aviator-fix-{vuln['vuln_id']}"
        commit_message = f"fix: Fortify Aviator remediation for vulnerability {vuln['vuln_id']}"
        create_branch_and_commit(repo_root, branch_name, commit_message, applied_files)

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
                "status": "pr_created",
                "vulnerability": vuln["vuln_id"],
                "files": [normalize_repo_path(filename) for filename in applied_files],
                "exploitability": exploitability,
                "pull_request": pull_request.get("html_url"),
            }
        )
        print(json.dumps({"results": decisions}, indent=2))
        return

    print(json.dumps({"results": decisions or [{"status": "no eligible remediation candidate found"}]}, indent=2))


if __name__ == "__main__":
    run()
