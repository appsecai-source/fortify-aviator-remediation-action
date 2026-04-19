from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, Optional


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
