import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ResultStatus = Literal["success", "warning", "error"]
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024


class ConfidenceTier(str, Enum):
    """How much weight a finding can bear. Stored as plain values; the CLI adds icons."""

    # Derived offline from authoritative data (e.g. numbering plans).
    VERIFIED = "verified"
    # Positive signal that also passed a control check.
    CONFIRMED = "confirmed"
    # Positive signal without a (conclusive) control check.
    LIKELY = "likely"
    # A lead for manual follow-up, not a finding.
    UNVERIFIED = "unverified"


class Evidence(BaseModel):
    """A raw server response kept as proof of a finding, fingerprinted at capture."""

    model_config = ConfigDict(frozen=True)

    source_url: str
    retrieved_at: datetime
    http_status: int | None
    content_type: str | None
    sha256: str
    size: int
    original_size: int
    truncated: bool
    content: bytes = Field(repr=False)

    @classmethod
    def capture(
        cls,
        source_url: str,
        http_status: int | None,
        content_type: str | None,
        content: bytes,
        max_bytes: int = MAX_EVIDENCE_BYTES,
    ) -> "Evidence":
        kept = content[:max_bytes]
        return cls(
            source_url=source_url,
            retrieved_at=datetime.now(timezone.utc),
            http_status=http_status,
            content_type=content_type,
            sha256=hashlib.sha256(kept).hexdigest(),
            size=len(kept),
            original_size=len(content),
            truncated=len(content) > max_bytes,
            content=kept,
        )

    def metadata(self) -> dict[str, Any]:
        """Everything except the raw bytes, JSON-ready."""
        return self.model_dump(mode="json", exclude={"content"})


class ModuleResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    module_name: str
    target: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: ResultStatus = "success"
    data: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    # Raw responses backing the findings; saved by a case store, never in JSON output.
    evidence: list[Evidence] = Field(default_factory=list, exclude=True)
