"""Central redaction service (STEP 10)."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SECRET_KEY_NAMES = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "id_token",
        "private_key",
        "session",
        "session_id",
        "session_token",
        "jwt",
        "authorization",
        "cookie",
        "set-cookie",
        "otp",
        "code",
        "reset_token",
        "verification_token",
        "token",
        "bearer",
        "client_secret",
        "database_url",
        "db_url",
    }
)

PII_KEY_NAMES = frozenset(
    {
        "email",
        "email_address",
        "phone",
        "phone_number",
        "mobile",
        "address",
        "street",
        "postal_code",
        "postcode",
        "date_of_birth",
        "dob",
        "birth_date",
        "iban",
        "bank_account",
        "card_number",
        "ssn",
        "national_id",
    }
)

_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_API_KEY_RE = re.compile(r"(?i)\b(?:sk|pk|api)[_-][A-Za-z0-9]{16,}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"\b(?:\+?\d[\d\-().\s]{7,}\d)\b")
_ENV_SECRET_RE = re.compile(
    r"(?im)^\s*([A-Z0-9_]*(?:SECRET|PASSWORD|PASS|TOKEN|PRIVATE_KEY|DATABASE_URL|DB_URL|API_KEY)[A-Z0-9_]*)\s*="
)


@dataclass(frozen=True, slots=True)
class RedactedValue:
    redacted: str
    fingerprint: str
    length: int
    category: str


def fingerprint_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _looks_secret_key(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    if lowered in SECRET_KEY_NAMES:
        return True
    return any(
        token in lowered
        for token in (
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "private_key",
            "otp",
            "passwd",
        )
    )


def _looks_pii_key(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    return lowered in PII_KEY_NAMES


class Redactor:
    def redact_scalar(
        self,
        value: str,
        *,
        key: str | None = None,
        category: str | None = None,
    ) -> RedactedValue:
        text = "" if value is None else str(value)
        detected = category
        if detected is None and key:
            if _looks_secret_key(key):
                detected = "secret"
            elif _looks_pii_key(key):
                detected = "pii"
        if detected is None:
            if _JWT_RE.search(text) or _BEARER_RE.search(text) or _API_KEY_RE.search(text):
                detected = "secret"
            elif _EMAIL_RE.fullmatch(text.strip()) or _PHONE_RE.fullmatch(text.strip()):
                detected = "pii"
            else:
                detected = "generic"

        if detected in {"secret", "pii"} or (key and _looks_secret_key(key)):
            placeholder = f"[{detected}:{fingerprint_value(text)}]"
            return RedactedValue(
                redacted=placeholder,
                fingerprint=fingerprint_value(text),
                length=len(text),
                category=detected,
            )
        return RedactedValue(
            redacted=text,
            fingerprint=fingerprint_value(text),
            length=len(text),
            category=detected,
        )

    def redact_headers(self, headers: dict[str, str]) -> dict[str, str]:
        return {
            key: self.redact_scalar(value, key=key).redacted
            for key, value in headers.items()
        }

    def redact_cookies(self, cookies: dict[str, str]) -> dict[str, str]:
        return {
            key: self.redact_scalar(value, key=key, category="secret").redacted
            for key, value in cookies.items()
        }

    def redact_query(self, url: str) -> str:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        redacted = [
            (
                key,
                self.redact_scalar(
                    value,
                    key=key,
                ).redacted
                if _looks_secret_key(key) or _looks_pii_key(key)
                else value,
            )
            for key, value in pairs
        ]
        return urlunsplit(
            parts._replace(query=urlencode(redacted, doseq=True))
        )

    def redact_json(self, payload: Any) -> Any:
        if isinstance(payload, dict):
            return {
                key: (
                    self.redact_scalar(str(value), key=str(key)).redacted
                    if isinstance(value, (str, int, float))
                    and (_looks_secret_key(str(key)) or _looks_pii_key(str(key)))
                    else self.redact_json(value)
                )
                for key, value in payload.items()
            }
        if isinstance(payload, list):
            return [self.redact_json(item) for item in payload]
        if isinstance(payload, str):
            return self.redact_text(payload)
        return payload

    def redact_form(self, fields: dict[str, str]) -> dict[str, str]:
        return {
            key: self.redact_scalar(value, key=key).redacted
            if _looks_secret_key(key) or _looks_pii_key(key)
            else value
            for key, value in fields.items()
        }

    def redact_text(self, text: str) -> str:
        if not text:
            return text
        scrubbed = _BEARER_RE.sub(
            lambda match: self.redact_scalar(
                match.group(0),
                category="secret",
            ).redacted,
            text,
        )
        scrubbed = _JWT_RE.sub(
            lambda match: self.redact_scalar(
                match.group(0),
                category="secret",
            ).redacted,
            scrubbed,
        )
        scrubbed = _API_KEY_RE.sub(
            lambda match: self.redact_scalar(
                match.group(0),
                category="secret",
            ).redacted,
            scrubbed,
        )
        scrubbed = _EMAIL_RE.sub(
            lambda match: self.redact_scalar(
                match.group(0),
                category="pii",
            ).redacted,
            scrubbed,
        )

        def _env_line(match: re.Match[str]) -> str:
            name = match.group(1)
            return (
                f"{name}=[{self.redact_scalar('x', key=name).category}:"
                f"{fingerprint_value(match.group(0))}]"
            )

        scrubbed = _ENV_SECRET_RE.sub(_env_line, scrubbed)

        # Key=value style secrets / PII in free text.
        scrubbed = re.sub(
            r"(?i)\b(password|passwd|token|api_key|apikey|reset_token|otp|secret|phone|email|mobile)\s*=\s*([^\s&]+)",
            lambda match: (
                f"{match.group(1)}="
                f"{self.redact_scalar(match.group(2), key=match.group(1)).redacted}"
            ),
            scrubbed,
        )
        return scrubbed

    def redact_url(self, url: str) -> str:
        return self.redact_query(url)

    def scrub_structure(self, data: Any) -> Any:
        if isinstance(data, dict):
            scrubbed: dict[str, Any] = {}
            for key, value in data.items():
                if isinstance(value, str) and (
                    _looks_secret_key(str(key)) or _looks_pii_key(str(key))
                ):
                    scrubbed[key] = self.redact_scalar(value, key=str(key)).redacted
                elif isinstance(value, str) and str(key).lower() in {
                    "url",
                    "uri",
                    "href",
                    "location",
                }:
                    scrubbed[key] = self.redact_url(value)
                else:
                    scrubbed[key] = self.scrub_structure(value)
            return scrubbed
        if isinstance(data, list):
            return [self.scrub_structure(item) for item in data]
        if isinstance(data, str):
            return self.redact_text(data)
        return data

    def scrub_report(self, report: dict[str, Any]) -> dict[str, Any]:
        """Deep-scrub a report/snapshot dict before persistence or export."""
        return self.scrub_structure(report)


_DEFAULT = Redactor()


def get_redactor(scan_context: Any | None = None) -> Redactor:
    if scan_context is not None:
        existing = getattr(scan_context, "redactor", None)
        if isinstance(existing, Redactor):
            return existing
    return _DEFAULT


def env_secret_key_names(body: str) -> list[str]:
    return sorted(set(_ENV_SECRET_RE.findall(body)))
