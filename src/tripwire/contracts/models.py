from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, PositiveInt, field_validator


class ToolCall(BaseModel):
    """A protected tool call attempted by an agent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)


class TaskContract(BaseModel):
    """Trusted task limits supplied by the application, not by the model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    principal: str = Field(min_length=1)
    scope: dict[str, str] = Field(default_factory=dict)
    allowed_tools: frozenset[str] = Field(min_length=1)
    allowed_destinations: tuple[str, ...] = Field(default_factory=tuple)
    max_actions: PositiveInt
    honeytokens: tuple[str, ...] = Field(default_factory=tuple)
    thresholds: dict[str, int] = Field(default_factory=dict)
    signature: str | None = None

    @field_validator("allowed_tools", mode="before")
    @classmethod
    def _coerce_allowed_tools(cls, value: object) -> object:
        if isinstance(value, list | tuple | set | frozenset):
            return frozenset(value)
        return value

    @field_validator("allowed_destinations", "honeytokens", mode="before")
    @classmethod
    def _coerce_tuple(cls, value: object) -> object:
        if value is None:
            return ()
        if isinstance(value, list | tuple):
            return tuple(value)
        return value

    @property
    def contract_hash(self) -> str:
        encoded = self.canonical_bytes(include_signature=True)
        return hashlib.sha256(encoded).hexdigest()

    def canonical_bytes(self, *, include_signature: bool = False) -> bytes:
        """Return the stable bytes used for hashing and optional signing."""
        payload = self.model_dump(mode="json")
        payload["allowed_tools"] = sorted(payload["allowed_tools"])
        if not include_signature:
            payload.pop("signature", None)
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def signature_for(self, key: str | bytes) -> str:
        """Return an HMAC-SHA256 signature for this contract without its signature field."""
        secret = key.encode("utf-8") if isinstance(key, str) else key
        return hmac.new(secret, self.canonical_bytes(), hashlib.sha256).hexdigest()

    def with_signature(self, key: str | bytes) -> TaskContract:
        """Return an immutable copy sealed with an HMAC-SHA256 signature."""
        return self.model_copy(update={"signature": self.signature_for(key)})

    def verify_signature(self, key: str | bytes) -> bool:
        if not self.signature:
            return False
        return hmac.compare_digest(self.signature, self.signature_for(key))
