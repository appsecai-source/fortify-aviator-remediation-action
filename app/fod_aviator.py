from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

import requests


@dataclass
class FoDConfig:
    base_url: str
    client_id: str
    client_secret: str
    tenant: str
    release_id: int
    user: str = ""
    password: str = ""
    oauth_scope: str = "api-tenant"
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
                client_id=os.environ.get("FOD_CLIENT_ID", ""),
                client_secret=os.environ.get("FOD_CLIENT_SECRET", ""),
                tenant=os.environ.get("FOD_TENANT", ""),
                release_id=int(os.environ["FOD_RELEASE_ID"]),
                user=os.environ.get("FOD_USER", ""),
                password=os.environ.get("FOD_PASSWORD", ""),
                oauth_scope=os.environ.get("FOD_OAUTH_SCOPE", "api-tenant"),
                verify_ssl=verify_env not in {"0", "false", "no"},
            )
        )

    def _request_token(self, token_url: str, data: Dict[str, str]) -> requests.Response:
        return self.session.post(
            token_url,
            data=data,
            timeout=self.config.timeout_seconds,
            verify=self.config.verify_ssl,
        )

    def _store_access_token(self, response: requests.Response) -> str:
        response.raise_for_status()
        payload = response.json()
        access_token = payload["access_token"]
        self._token = access_token
        self.session.headers.update({"Authorization": f"Bearer {access_token}"})
        return access_token

    def _raise_auth_error(self, response: requests.Response) -> None:
        message = (
            "Fortify on Demand authentication failed. "
            "Verify that you are using a valid FoD API key/secret or FoD user/PAT, "
            "that the remediation job is targeting the FoD API root URL, and that the requested "
            f"OAuth scope '{self.config.oauth_scope}' is allowed."
        )
        try:
            payload = response.json()
            error = payload.get("error")
            error_description = payload.get("error_description") or payload.get("message")
            if error or error_description:
                detail = " ".join(part for part in [error, error_description] if part)
                message = f"{message} FoD response: {detail}"
        except ValueError:
            pass
        raise requests.HTTPError(message, response=response)

    def _qualified_username(self) -> str:
        username = self.config.user.strip()
        if not username:
            return ""
        if "\\" in username or not self.config.tenant.strip():
            return username
        return f"{self.config.tenant.strip()}\\{username}"

    def authenticate(self) -> str:
        token_url = f"{self.config.base_url}/oauth/token"

        if self.config.client_id and self.config.client_secret:
            data = {
                "scope": self.config.oauth_scope,
                "grant_type": "client_credentials",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
            }
            response = self._request_token(token_url=token_url, data=data)
            if response.ok:
                return self._store_access_token(response)
            if not (self.config.user and self.config.password):
                self._raise_auth_error(response)

        qualified_username = self._qualified_username()
        if qualified_username and self.config.password:
            data = {
                "scope": self.config.oauth_scope,
                "grant_type": "password",
                "username": qualified_username,
                "password": self.config.password,
            }
            response = self._request_token(token_url=token_url, data=data)
            if response.ok:
                return self._store_access_token(response)
            self._raise_auth_error(response)

        raise RuntimeError(
            "Missing Fortify on Demand credentials. Set FOD_CLIENT_ID and FOD_CLIENT_SECRET, "
            "or set FOD_USER and FOD_PASSWORD/FOD_PAT. For password grant, provide FOD_USER as "
            "'tenant\\\\username' or set FOD_TENANT plus FOD_USER."
        )

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
        only_guidance_available: bool = False,
        limit: Optional[int] = None,
        offset: int = 0,
        fortify_aviator: bool = True,
        severity_string: str = "",
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "offset": offset,
            "fortifyAviator": str(fortify_aviator).lower(),
        }
        if limit is not None:
            params["limit"] = limit
        if severity_string:
            params["severityString"] = severity_string
        # Query FoD vulnerabilities that have been processed by Fortify Aviator.
        return self._get(f"/api/v3/releases/{self.config.release_id}/vulnerabilities", params=params)

    def iter_vulnerabilities(
        self,
        fortify_aviator: bool = True,
        severity_strings: Optional[Sequence[str]] = None,
    ) -> List[Dict[str, Any]]:
        requested_severities = [severity.strip() for severity in (severity_strings or []) if severity and severity.strip()]
        requested_severity_set = {
            normalize_severity_label(severity).lower()
            for severity in requested_severities
            if normalize_severity_label(severity)
        }
        if not requested_severities:
            requested_severities = [""]

        collected: List[Dict[str, Any]] = []
        seen_ids = set()

        for severity_string in requested_severities:
            offset = 0
            total_count: Optional[int] = None

            while total_count is None or offset < total_count:
                payload = self.list_vulnerabilities(
                    offset=offset,
                    fortify_aviator=fortify_aviator,
                    severity_string=severity_string,
                )
                items = payload.get("items", [])
                total_count = int(payload.get("totalCount") or 0)
                if not items:
                    break

                for item in items:
                    item_id = item.get("id") or item.get("issueId") or item.get("vulnId")
                    item_severity = normalize_severity_label(
                        item.get("severityString") or item.get("severity") or ""
                    ).lower()
                    if requested_severity_set and item_severity not in requested_severity_set:
                        continue
                    if item_id in seen_ids:
                        continue
                    seen_ids.add(item_id)
                    collected.append(item)

                offset += len(items)

        return collected

    def get_aviator_guidance(self, vuln_id: int) -> Optional[Dict[str, Any]]:
        try:
            return self._get(
                f"/api/v3/releases/{self.config.release_id}/vulnerabilities/{vuln_id}/aviator-remediation-guidance"
            )
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code in (404, 422):
                return None
            raise

    @staticmethod
    def normalize_vulnerability(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        severity = normalize_severity_label(
            vulnerability.get("severityString") or vulnerability.get("severity") or "Unknown"
        )
        auditor_status = str(vulnerability.get("auditorStatus") or "").strip()
        legacy_confidence = (
            vulnerability.get("confidence")
            or vulnerability.get("accuracy")
            or vulnerability.get("priorityOrder")
            or "Unknown"
        )
        confidence = auditor_status or str(legacy_confidence)
        confidence_normalized = normalize_confidence(auditor_status, str(legacy_confidence))
        return {
            # The remediation-guidance endpoint expects the numeric vulnerability id from the
            # release findings payload, not the GUID-style vulnId field.
            "vuln_id": vulnerability.get("id") or vulnerability.get("issueId") or vulnerability.get("vulnId"),
            "vuln_guid": vulnerability.get("vulnId"),
            "instance_id": vulnerability.get("instanceId"),
            "category": vulnerability.get("category") or vulnerability.get("kingdom") or vulnerability.get("issueName"),
            "severity": severity,
            "file_path": vulnerability.get("fileName") or vulnerability.get("primaryLocationFull"),
            "line": int(vulnerability.get("lineNumber") or vulnerability.get("line") or 0),
            "cwe": vulnerability.get("cwe") or vulnerability.get("cweId"),
            "confidence": str(confidence),
            "confidence_normalized": confidence_normalized,
            "auditor_status": auditor_status or "Unknown",
            "remediation_guidance_available": bool(
                vulnerability.get("aviatorRemediationGuidanceAvailable")
                if "aviatorRemediationGuidanceAvailable" in vulnerability
                else vulnerability.get("remediationGuidanceAvailable", False)
            ),
            "scan_type": vulnerability.get("analysisType") or vulnerability.get("scanType") or vulnerability.get("scantype"),
            "fortify_aviator": bool(vulnerability.get("fortifyAviator", False)),
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


def normalize_severity_label(value: Any) -> str:
    if isinstance(value, int):
        numeric_mapping = {
            4: "Critical",
            3: "High",
            2: "Medium",
            1: "Low",
            0: "Unknown",
        }
        return numeric_mapping.get(value, "Unknown")

    lowered = str(value or "").strip().lower()
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Informational",
        "best practice": "Best Practice",
        "unknown": "Unknown",
    }
    return mapping.get(lowered, str(value or "").strip() or "Unknown")


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


def normalize_legacy_confidence(value: str) -> str:
    lowered = str(value or "").strip().lower()
    if lowered in {"5", "high", "confirmed", "true_positive", "tp"}:
        return "high"
    if lowered in {"4", "medium", "moderate"}:
        return "medium"
    if lowered in {"3", "low", "suspicious"}:
        return "low"
    return lowered or "unknown"


def normalize_confidence(auditor_status: str, fallback_value: str = "") -> str:
    normalized_status = " ".join(str(auditor_status or "").strip().lower().split())

    if normalized_status == "remediation required":
        return "high"
    if normalized_status == "suspicious":
        return "medium"
    if normalized_status == "proposed not an issue":
        return "false_positive"
    if normalized_status in {"remediation deferred", "remediation deffered", "risk mitigated"}:
        return "manual_intervention"
    if normalized_status == "pending review":
        return "pending_review"

    return normalize_legacy_confidence(fallback_value)
