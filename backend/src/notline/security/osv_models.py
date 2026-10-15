from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class OsvAdvisory(BaseModel):
    """Normalized advisory returned for an exact package version query."""

    osv_id: str
    aliases: list[str] = Field(default_factory=list)
    summary: str | None = None
    details: str | None = None
    published: str | None = None
    modified: str | None = None
    withdrawn: str | None = None
    severity: list[dict[str, str]] = Field(default_factory=list)
    reference_urls: list[str] = Field(default_factory=list)

    @classmethod
    def from_osv(cls, payload: dict[str, Any]) -> OsvAdvisory:
        references = payload.get("references", [])
        severity = payload.get("severity", [])
        return cls(
            osv_id=payload["id"],
            aliases=[alias for alias in payload.get("aliases", []) if alias],
            summary=payload.get("summary"),
            details=payload.get("details"),
            published=payload.get("published"),
            modified=payload.get("modified"),
            withdrawn=payload.get("withdrawn"),
            severity=[
                {key: value for key, value in entry.items() if isinstance(value, str)}
                for entry in severity
                if isinstance(entry, dict)
            ],
            reference_urls=[
                reference["url"]
                for reference in references
                if isinstance(reference, dict) and reference.get("url")
            ],
        )
