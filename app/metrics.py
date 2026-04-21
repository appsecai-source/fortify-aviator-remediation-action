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


def _pct(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100.0, 1)


def _fmt_pct(numerator: int, denominator: int) -> str:
    return f"{_pct(numerator, denominator):.1f}%"


def synthesize_remediation_metrics(metrics: Mapping[str, Any]) -> Dict[str, Any]:
    overview = dict(metrics.get("overview", {}))
    total_findings = int(overview.get("total_findings", 0))
    guidance_available = int(overview.get("guidance_available", 0))
    eligible = int(overview.get("eligible_for_autofix", 0))
    applied = int(overview.get("autofix_applied", 0))
    pr_groups_published = int(overview.get("pr_groups_published", 0))
    pr_group_errors = int(overview.get("pr_group_errors", 0))

    blocker_candidates = [
        ("Fix failures", int(overview.get("fix_failures", 0))),
        ("Patch apply failures", int(overview.get("patch_apply_failures", 0))),
        ("No fix suggestion", int(overview.get("no_fix_suggestion", 0))),
        ("Other skips", int(overview.get("other_skips_combined", 0))),
        ("False positives", int(overview.get("false_positives", 0))),
        ("Manual intervention", int(overview.get("manual_intervention", 0))),
    ]
    top_blockers = [
        {"label": label, "count": count}
        for label, count in sorted(blocker_candidates, key=lambda item: item[1], reverse=True)
        if count > 0
    ][:3]

    return {
        "reviewed_findings": total_findings,
        "guided_findings": guidance_available,
        "guided_rate_pct": _pct(guidance_available, total_findings),
        "eligible_findings": eligible,
        "eligible_rate_pct": _pct(eligible, total_findings),
        "autofixes_applied": applied,
        "autofix_success_rate_pct": _pct(applied, eligible),
        "pr_groups_published": pr_groups_published,
        "pr_group_errors": pr_group_errors,
        "remediation_prs_published": pr_groups_published,
        "remediation_pr_errors": pr_group_errors,
        "top_blockers": top_blockers,
    }


def _bucket_label_for_outcome(outcome: str) -> str:
    mapping = {
        "no_fix_suggestion": "No fix suggestion",
        "severity_filtered_out": "Outside severity scope",
        "false_positive": "False positive",
        "manual_intervention": "Manual intervention required",
        "patch_apply_failure": "Patch apply failure",
        "validation_failure": "Validation failure",
        "fix_failure": "PR publication failure",
        "out_of_scope": "Out of scope",
        "policy_skipped": "Policy skipped",
        "other_skipped": "Other skip",
    }
    return mapping.get(outcome, "Other skip")


def _bucket_detail_for_record(record: Mapping[str, Any]) -> str:
    outcome = str(record.get("outcome") or "").strip()
    detail = str(record.get("detail") or "").strip()

    if outcome == "no_fix_suggestion":
        return ""
    if outcome == "false_positive":
        return str(record.get("auditor_status") or detail or "").strip()
    if outcome == "manual_intervention":
        return str(record.get("auditor_status") or detail or "").strip()
    return detail


def _format_severity_mix(severity_counts: Mapping[str, int]) -> str:
    parts = [
        f"{severity} {count}"
        for severity, count in sorted(severity_counts.items(), key=lambda item: _severity_sort_key(item[0]))
    ]
    return ", ".join(parts)


def _md_cell(value: Any, max_chars: int | None = None) -> str:
    text = str(value or "-").replace("\n", "<br>").replace("|", "\\|")
    if max_chars is not None and len(text) > max_chars:
        return text[: max_chars - 3].rstrip() + "..."
    return text


def synthesize_result_summary(
    records: Iterable[Mapping[str, Any]],
    decisions: Iterable[Mapping[str, Any]],
    *,
    max_buckets: int = 8,
    max_samples: int = 5,
) -> Dict[str, Any]:
    pr_activity = []
    unfixed_buckets: Dict[tuple[str, str], Dict[str, Any]] = {}

    for decision in decisions:
        status = str(decision.get("status") or "").strip()
        if status not in {"pr_created", "pr_already_exists", "error"}:
            continue

        pr_activity.append(
            {
                "result": {
                    "pr_created": "PR created",
                    "pr_already_exists": "PR updated",
                    "error": "PR failed",
                }[status],
                "severity": str(decision.get("severity") or "Unknown"),
                "category": str(decision.get("category") or "Uncategorized"),
                "included_findings": len(decision.get("vulnerabilities", [])),
                "skipped_during_apply": len(decision.get("skipped_vulnerabilities", [])),
                "pull_request": decision.get("pull_request"),
                "error": decision.get("error"),
            }
        )

    pr_activity.sort(key=lambda item: (_severity_sort_key(item["severity"]), item["category"]))

    for record in records:
        outcome = str(record.get("outcome") or "").strip()
        if outcome in {"", "eligible", "autofix_applied"}:
            continue

        label = _bucket_label_for_outcome(outcome)
        detail = _bucket_detail_for_record(record)
        key = (label, detail)
        bucket = unfixed_buckets.setdefault(
            key,
            {
                "reason": label,
                "detail": detail or None,
                "count": 0,
                "severity_counts": {},
                "sample_vulnerabilities": [],
                "sample_categories": [],
            },
        )
        severity = str(record.get("severity") or "Unknown").strip() or "Unknown"
        category = str(record.get("category") or "Uncategorized").strip() or "Uncategorized"
        vulnerability = record.get("vulnerability")

        bucket["count"] += 1
        bucket["severity_counts"][severity] = int(bucket["severity_counts"].get(severity, 0)) + 1
        if vulnerability not in bucket["sample_vulnerabilities"] and len(bucket["sample_vulnerabilities"]) < max_samples:
            bucket["sample_vulnerabilities"].append(vulnerability)
        if category not in bucket["sample_categories"] and len(bucket["sample_categories"]) < max_samples:
            bucket["sample_categories"].append(category)

    sorted_buckets = sorted(
        unfixed_buckets.values(),
        key=lambda item: (-int(item["count"]), item["reason"], item["detail"] or ""),
    )
    visible_buckets = []
    for bucket in sorted_buckets[:max_buckets]:
        visible_buckets.append(
            {
                "reason": bucket["reason"],
                "detail": bucket["detail"],
                "count": bucket["count"],
                "severity_mix": _format_severity_mix(bucket["severity_counts"]),
                "sample_vulnerabilities": bucket["sample_vulnerabilities"],
                "sample_categories": bucket["sample_categories"],
            }
        )

    return {
        "pull_request_activity": pr_activity,
        "unfixed_findings": visible_buckets,
        "additional_unfixed_buckets": max(len(sorted_buckets) - len(visible_buckets), 0),
    }


def render_remediation_metrics_markdown(metrics: Mapping[str, Any]) -> str:
    overview = dict(metrics.get("overview", {}))
    by_severity = list(metrics.get("by_severity", []))
    summary = synthesize_remediation_metrics(metrics)
    total_findings = int(overview.get("total_findings", 0))
    guidance_available = int(overview.get("guidance_available", 0))
    eligible = int(overview.get("eligible_for_autofix", 0))
    applied = int(overview.get("autofix_applied", 0))
    pr_groups_published = int(overview.get("pr_groups_published", 0))
    pr_group_errors = int(overview.get("pr_group_errors", 0))
    top_blockers = list(summary.get("top_blockers", []))
    blocker_text = ", ".join(
        f"{item['label'].lower()} ({item['count']})"
        for item in top_blockers
    ) or "none"

    lines = [
        "## Fortify Aviator Remediation Summary",
        "",
        "### At A Glance",
        "",
        f"- Reviewed **{total_findings}** findings.",
        f"- Aviator returned fix suggestions for **{guidance_available}** findings ({_fmt_pct(guidance_available, total_findings)} of all findings).",
        f"- **{eligible}** findings were eligible for autofix, and **{applied}** were applied ({_fmt_pct(applied, eligible)} success on eligible findings).",
        f"- Published **{pr_groups_published}** remediation PRs; **{pr_group_errors}** PR publications still failed during creation or update.",
        f"- Main blockers were {blocker_text}.",
        "",
        "### Remediation Funnel",
        "",
        "| Stage | Findings | Share Of Total | Conversion |",
        "| --- | ---: | ---: | ---: |",
        f"| Reviewed | {total_findings} | 100.0% | - |",
        f"| Guidance available | {guidance_available} | {_fmt_pct(guidance_available, total_findings)} | {_fmt_pct(guidance_available, total_findings)} |",
        f"| Eligible for autofix | {eligible} | {_fmt_pct(eligible, total_findings)} | {_fmt_pct(eligible, guidance_available)} |",
        f"| Autofix applied | {applied} | {_fmt_pct(applied, total_findings)} | {_fmt_pct(applied, eligible)} |",
        "",
        "### What Blocked More Fixes",
        "",
        "| Outcome | Findings | Share Of Total |",
        "| --- | ---: | ---: |",
        f"| No fix suggestion | {int(overview.get('no_fix_suggestion', 0))} | {_fmt_pct(int(overview.get('no_fix_suggestion', 0)), total_findings)} |",
        f"| Patch apply failure | {int(overview.get('patch_apply_failures', 0))} | {_fmt_pct(int(overview.get('patch_apply_failures', 0)), total_findings)} |",
        f"| Fix failure | {int(overview.get('fix_failures', 0))} | {_fmt_pct(int(overview.get('fix_failures', 0)), total_findings)} |",
        f"| Other skips | {int(overview.get('other_skips_combined', 0))} | {_fmt_pct(int(overview.get('other_skips_combined', 0)), total_findings)} |",
        "",
        "### Severity Breakdown",
        "",
        "| Severity | Findings | Eligible | Fixed | Success On Eligible | No Suggestion | Patch Failures | Fix Failures | PRs |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]

    for row in by_severity:
        lines.append(
            "| {severity} | {total_findings} | {eligible_for_autofix} | {autofix_applied} | "
            "{success_rate} | {no_fix_suggestion} | {patch_apply_failures} | "
            "{fix_failures} | {pr_groups_published} |".format(
                **row,
                success_rate=_fmt_pct(
                    int(row.get("autofix_applied", 0)),
                    int(row.get("eligible_for_autofix", 0)),
                ),
            )
        )

    return "\n".join(lines) + "\n"


def render_result_summary_markdown(result_summary: Mapping[str, Any]) -> str:
    pr_activity = list(result_summary.get("pull_request_activity", []))
    unfixed_findings = list(result_summary.get("unfixed_findings", []))
    additional_unfixed = int(result_summary.get("additional_unfixed_buckets", 0))

    lines = [
        "### PR Activity",
        "",
        "| Result | Severity | Category | Included | Skipped While Preparing PR | Reference |",
        "| --- | --- | --- | ---: | ---: | --- |",
    ]
    if pr_activity:
        for item in pr_activity:
            reference = item.get("pull_request") or item.get("error") or "-"
            lines.append(
                f"| {_md_cell(item['result'])} | {_md_cell(item['severity'])} | {_md_cell(item['category'])} | "
                f"{item['included_findings']} | {item['skipped_during_apply']} | {_md_cell(reference, 140)} |"
            )
    else:
        lines.append("| No PR activity | - | - | 0 | 0 | - |")

    lines.extend(
        [
            "",
            "### Largest Unfixed Buckets",
            "",
            "| Reason | Findings | Severity Mix | Example Categories | Sample Vulnerabilities |",
            "| --- | ---: | --- | --- | --- |",
        ]
    )
    if unfixed_findings:
        for item in unfixed_findings:
            reason = item["reason"]
            if item.get("detail"):
                reason = f"{reason}: {item['detail']}"
            lines.append(
                f"| {_md_cell(reason, 140)} | {item['count']} | {_md_cell(item['severity_mix'])} | "
                f"{_md_cell(', '.join(str(value) for value in item.get('sample_categories', [])) or '-')} | "
                f"{_md_cell(', '.join(str(value) for value in item.get('sample_vulnerabilities', [])) or '-')} |"
            )
    else:
        lines.append("| None | 0 | - | - | - |")

    if additional_unfixed > 0:
        lines.extend(
            [
                "",
                f"{additional_unfixed} additional low-volume unfixed buckets were omitted from this summary.",
            ]
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
