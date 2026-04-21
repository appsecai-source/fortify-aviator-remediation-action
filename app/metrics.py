from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, Mapping, Optional


@dataclass
class FindingLifecycle:
    vuln_id: str
    first_seen: datetime
    remediated_at: Optional[datetime]
    severity: str
    status: str


@dataclass
class RemediationTelemetry:
    auto_prs_created: int = 0
    prs_merged: int = 0
    comment_only_fallbacks: int = 0
    patch_apply_failures: int = 0
    guidance_generated: int = 0
    guidance_consumed: int = 0


def mean_time_to_remediate(findings: Iterable[FindingLifecycle]) -> Optional[float]:
    durations = []
    for finding in findings:
        if finding.remediated_at:
            durations.append((finding.remediated_at - finding.first_seen).total_seconds() / 86400.0)
    if not durations:
        return None
    return round(sum(durations) / len(durations), 2)


def backlog_burndown(findings: Iterable[FindingLifecycle]) -> Dict[str, int]:
    open_count = 0
    remediated_count = 0
    for finding in findings:
        if finding.remediated_at:
            remediated_count += 1
        else:
            open_count += 1
    return {"open": open_count, "remediated": remediated_count}


def mttr_reduction_pct(previous_mttr_days: Optional[float], current_mttr_days: Optional[float]) -> Optional[float]:
    if previous_mttr_days is None or current_mttr_days is None or previous_mttr_days == 0:
        return None
    return round(((previous_mttr_days - current_mttr_days) / previous_mttr_days) * 100.0, 2)


def executive_summary(
    previous_mttr_days: Optional[float],
    current_mttr_days: Optional[float],
    open_before: int,
    open_now: int,
    telemetry: Optional[RemediationTelemetry] = None,
) -> Dict[str, Optional[float]]:
    reduction = mttr_reduction_pct(previous_mttr_days, current_mttr_days)
    burndown = None
    if open_before > 0:
        burndown = round(((open_before - open_now) / open_before) * 100.0, 2)

    output: Dict[str, Optional[float]] = {
        "previous_mttr_days": previous_mttr_days,
        "current_mttr_days": current_mttr_days,
        "mttr_reduction_pct": reduction,
        "backlog_burndown_pct": burndown,
    }

    if telemetry is not None:
        output.update(
            {
                "auto_prs_created": telemetry.auto_prs_created,
                "prs_merged": telemetry.prs_merged,
                "comment_only_fallbacks": telemetry.comment_only_fallbacks,
                "patch_apply_failures": telemetry.patch_apply_failures,
                "guidance_generated": telemetry.guidance_generated,
                "guidance_consumed": telemetry.guidance_consumed,
            }
        )
    return output


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def _severity_sort_key(severity: str) -> tuple[int, str]:
    label = str(severity or "Unknown").strip() or "Unknown"
    return (SEVERITY_ORDER.get(label.lower(), len(SEVERITY_ORDER)), label)


def _new_remediation_bucket() -> Dict[str, int]:
    return {
        "total_findings": 0,
        "guidance_available": 0,
        "structured_fix_suggestions": 0,
        "eligible_for_autofix": 0,
        "autofix_applied": 0,
        "no_fix_suggestion": 0,
        "patch_apply_failures": 0,
        "fix_failures": 0,
        "false_positives": 0,
        "manual_intervention": 0,
        "severity_filtered_out": 0,
        "out_of_scope": 0,
        "policy_skips": 0,
        "other_skips": 0,
        "pending_review_autofixed": 0,
        "pr_groups_created": 0,
        "pr_groups_updated": 0,
        "pr_group_errors": 0,
    }


def _combined_other_skips(bucket: Mapping[str, int]) -> int:
    return (
        int(bucket.get("severity_filtered_out", 0))
        + int(bucket.get("out_of_scope", 0))
        + int(bucket.get("policy_skips", 0))
        + int(bucket.get("other_skips", 0))
    )


def summarize_remediation_outcomes(
    records: Iterable[Mapping[str, Any]],
    decisions: Iterable[Mapping[str, Any]],
) -> Dict[str, Any]:
    totals = _new_remediation_bucket()
    by_severity: Dict[str, Dict[str, int]] = {}

    def ensure_bucket(severity: str) -> Dict[str, int]:
        label = str(severity or "Unknown").strip() or "Unknown"
        if label not in by_severity:
            by_severity[label] = _new_remediation_bucket()
        return by_severity[label]

    for record in records:
        severity = str(record.get("severity") or "Unknown").strip() or "Unknown"
        bucket = ensure_bucket(severity)
        outcome = str(record.get("outcome") or "").strip()
        auditor_status = str(record.get("auditor_status") or "").strip().lower()

        for target in (totals, bucket):
            target["total_findings"] += 1
            if record.get("guidance_available"):
                target["guidance_available"] += 1
            if record.get("structured_fix_available"):
                target["structured_fix_suggestions"] += 1
            if record.get("eligible"):
                target["eligible_for_autofix"] += 1

            if outcome == "autofix_applied":
                target["autofix_applied"] += 1
            elif outcome == "no_fix_suggestion":
                target["no_fix_suggestion"] += 1
            elif outcome == "patch_apply_failure":
                target["patch_apply_failures"] += 1
            elif outcome == "fix_failure":
                target["fix_failures"] += 1
            elif outcome == "false_positive":
                target["false_positives"] += 1
            elif outcome == "manual_intervention":
                target["manual_intervention"] += 1
            elif outcome == "severity_filtered_out":
                target["severity_filtered_out"] += 1
            elif outcome == "out_of_scope":
                target["out_of_scope"] += 1
            elif outcome == "policy_skipped":
                target["policy_skips"] += 1
            elif outcome and outcome not in {"eligible"}:
                target["other_skips"] += 1

            if auditor_status == "pending review" and outcome == "autofix_applied":
                target["pending_review_autofixed"] += 1

    for decision in decisions:
        severity = str(decision.get("severity") or "").strip()
        if not severity:
            continue
        bucket = ensure_bucket(severity)
        status = str(decision.get("status") or "").strip()
        for target in (totals, bucket):
            if status == "pr_created":
                target["pr_groups_created"] += 1
            elif status == "pr_already_exists":
                target["pr_groups_updated"] += 1
            elif status == "error":
                target["pr_group_errors"] += 1

    overview = {
        **totals,
        "pr_groups_published": totals["pr_groups_created"] + totals["pr_groups_updated"],
        "other_skips_combined": _combined_other_skips(totals),
    }

    by_severity_rows = []
    for severity in sorted(by_severity, key=_severity_sort_key):
        bucket = by_severity[severity]
        by_severity_rows.append(
            {
                "severity": severity,
                **bucket,
                "pr_groups_published": bucket["pr_groups_created"] + bucket["pr_groups_updated"],
                "other_skips_combined": _combined_other_skips(bucket),
            }
        )

    return {
        "overview": overview,
        "by_severity": by_severity_rows,
    }


def render_remediation_metrics_markdown(metrics: Mapping[str, Any]) -> str:
    overview = dict(metrics.get("overview", {}))
    by_severity = list(metrics.get("by_severity", []))

    overview_rows = [
        ("Findings Fetched", overview.get("total_findings", 0)),
        ("Guidance Available", overview.get("guidance_available", 0)),
        ("Structured Fix Suggestions", overview.get("structured_fix_suggestions", 0)),
        ("Eligible For Autofix", overview.get("eligible_for_autofix", 0)),
        ("Autofix Applied", overview.get("autofix_applied", 0)),
        ("PR Groups Created", overview.get("pr_groups_created", 0)),
        ("PR Groups Updated", overview.get("pr_groups_updated", 0)),
        ("PR Group Errors", overview.get("pr_group_errors", 0)),
        ("No Fix Suggestion", overview.get("no_fix_suggestion", 0)),
        ("Patch Apply Failures", overview.get("patch_apply_failures", 0)),
        ("Fix Failures", overview.get("fix_failures", 0)),
        ("False Positives Skipped", overview.get("false_positives", 0)),
        ("Manual Intervention Skipped", overview.get("manual_intervention", 0)),
        ("Other Skips", overview.get("other_skips_combined", 0)),
        ("Pending Review Autofixed", overview.get("pending_review_autofixed", 0)),
    ]

    lines = [
        "## Fortify Aviator Remediation Metrics",
        "",
        "### Overall",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
    ]
    lines.extend(f"| {label} | {value} |" for label, value in overview_rows)
    lines.extend(
        [
            "",
            "### By Severity",
            "",
            "| Severity | Findings | Guidance | Eligible | Autofix Applied | PR Groups | No Fix Suggestion | Patch Failures | Fix Failures | False Positives | Manual Intervention | Other Skips |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )

    for row in by_severity:
        lines.append(
            "| {severity} | {total_findings} | {guidance_available} | {eligible_for_autofix} | "
            "{autofix_applied} | {pr_groups_published} | {no_fix_suggestion} | "
            "{patch_apply_failures} | {fix_failures} | {false_positives} | "
            "{manual_intervention} | {other_skips_combined} |".format(**row)
        )

    return "\n".join(lines) + "\n"


def publish_remediation_metrics_markdown(markdown: str) -> str:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if not summary_path:
        return ""

    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write(markdown)
        if not markdown.endswith("\n"):
            handle.write("\n")
    return summary_path
