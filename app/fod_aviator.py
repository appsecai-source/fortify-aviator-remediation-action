from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests


@dataclass
class FoDConfig:
    base_url: str
    client_id: str
    client_secret: str
    tenant: str
    release_id: int
    timeout_seconds: int = 60
    verify_ssl: bool = True


@dataclass
class CodeContext:
    before: int
    after: int
    value: str


@dataclass
class CodeChange:
    line_from: int
    line_to: int
    original_code: str
    new_code: str
    context: Optional[CodeContext] = None


@dataclass
class FileHash:
    type: str
    value: str


@dataclass
class FileRemediation:
    filename: str
    hashes: List[FileHash] = field(default_factory=list)
    changes: List[CodeChange] = field(default_factory=list)


@dataclass
class AviatorGuidance:
    audit_comment: str
    file_changes: List[FileRemediation]
    instance_id: str
    write_date: str
    raw: Dict[str, Any] = field(default_factory=dict)


class FoDAviatorClient:
    """
    Thin client for OpenText Core Application Security Fortify on Demand.
    """

    def __init__(self, config: FoDConfig) -> None:
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})
        self._token: Optional[str] = None

    @classmethod
    def from_env(cls) -> "FoDAviatorClient":
        verify_env = os.environ.get("FOD_VERIFY_SSL", "true").strip().lower()
        return cls(
            FoDConfig(
                base_url=os.environ["FOD_BASE_URL"].rstrip("/"),
                client_id=os.environ["FOD_CLIENT_ID"],
                client_secret=os.environ["FOD_CLIENT_SECRET"],
                tenant=os.environ.get("FOD_TENANT", ""),
                release_id=int(os.environ["FOD_RELEASE_ID"]),
                verify_ssl=verify_env not in {"0", "false", "no"},
            )
        )

    def authenticate(self) -> str:
        token_url = f"{self.config.base_url}/oauth/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        if self.config.tenant:
            data["tenant"] = self.config.tenant
        response = self.session.post(
            token_url,
            data=data,
            timeout=self.config.timeout_seconds,
            verify=self.config.verify_ssl,
        )
        response.raise_for_status()
        payload = response.json()
        access_token = payload["access_token"]
        self._token = access_token
        self.session.headers.update({"Authorization": f"Bearer {access_token}"})
        return access_token

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        if not self._token:
            self.authenticate()
        response = self.session.get(
            f"{self.config.base_url}{path}",
            params=params,
            timeout=self.config.timeout_seconds,
            verify=self.config.verify_ssl,
        )
        response.raise_for_status()
        if "application/json" in response.headers.get("Content-Type", ""):
            return response.json()
        return response.text

    def list_vulnerabilities(
        self,
        only_guidance_available: bool = True,
        limit: int = 200,
        offset: int = 0,
        extra_filters: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        filters: List[str] = []
        if only_guidance_available:
            filters.append("remediationGuidanceAvailable:true")
        if extra_filters:
            filters.extend(extra_filters)
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if filters:
            params["filters"] = "+".join(filters)
        return self._get(f"/api/v3/releases/{self.config.release_id}/vulnerabilities", params=params)

    def get_aviator_guidance(self, vuln_id: int) -> Optional[Dict[str, Any]]:
        try:
            return self._get(
                f"/api/v3/releases/{self.config.release_id}/vulnerabilities/{vuln_id}/aviatorremediation-guidance"
            )
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code in (404, 422):
                return None
            raise

    @staticmethod
    def normalize_vulnerability(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        severity = vulnerability.get("severityString") or vulnerability.get("severity") or "Unknown"
        confidence = (
            vulnerability.get("confidence")
            or vulnerability.get("accuracy")
            or vulnerability.get("priorityOrder")
            or "Unknown"
        )
        return {
            "vuln_id": vulnerability.get("vulnId") or vulnerability.get("id") or vulnerability.get("issueId"),
            "instance_id": vulnerability.get("instanceId"),
            "category": vulnerability.get("category") or vulnerability.get("kingdom") or vulnerability.get("issueName"),
            "severity": severity,
            "file_path": vulnerability.get("fileName") or vulnerability.get("primaryLocationFull"),
            "line": int(vulnerability.get("lineNumber") or vulnerability.get("line") or 0),
            "cwe": vulnerability.get("cwe") or vulnerability.get("cweId"),
            "confidence": str(confidence),
            "confidence_normalized": normalize_confidence(str(confidence)),
            "remediation_guidance_available": bool(vulnerability.get("remediationGuidanceAvailable", False)),
            "scan_type": vulnerability.get("analysisType") or vulnerability.get("scanType"),
            "analysis": vulnerability.get("analysis"),
            "raw": vulnerability,
        }

    @staticmethod
    def parse_aviator_guidance(payload: Optional[Dict[str, Any]]) -> Optional[AviatorGuidance]:
        if not payload:
            return None

        file_changes: List[FileRemediation] = []
        for file_item in payload.get("FileChanges", []):
            hashes = [FileHash(type=item.get("type", ""), value=item.get("Value", "")) for item in file_item.get("Hash", [])]

            changes: List[CodeChange] = []
            for change in file_item.get("Change", []):
                context_payload = change.get("Context")
                context = None
                if context_payload:
                    context = CodeContext(
                        before=int(context_payload.get("before", 0)),
                        after=int(context_payload.get("after", 0)),
                        value=context_payload.get("Value", ""),
                    )
                changes.append(
                    CodeChange(
                        line_from=int(change.get("LineFrom", 0)),
                        line_to=int(change.get("LineTo", 0)),
                        original_code=change.get("OriginalCode", ""),
                        new_code=change.get("NewCode", ""),
                        context=context,
                    )
                )

            file_changes.append(
                FileRemediation(
                    filename=file_item.get("Filename", ""),
                    hashes=hashes,
                    changes=changes,
                )
            )

        return AviatorGuidance(
            audit_comment=payload.get("AuditComment", ""),
            file_changes=file_changes,
            instance_id=payload.get("instanceId", ""),
            write_date=payload.get("writeDate", ""),
            raw=payload,
        )


def severity_rank(severity: str) -> int:
    mapping = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "informational": 1,
        "best practice": 1,
        "unknown": 0,
    }
    return mapping.get(str(severity).strip().lower(), 0)


def normalize_confidence(value: str) -> str:
    lowered = str(value or "").strip().lower()
    if lowered in {"5", "high", "confirmed", "true_positive", "tp"}:
        return "high"
    if lowered in {"4", "medium", "moderate"}:
        return "medium"
    if lowered in {"3", "low", "suspicious"}:
        return "low"
    return lowered or "unknown"
