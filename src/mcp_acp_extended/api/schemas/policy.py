"""Policy API schemas."""

from __future__ import annotations

__all__ = [
    "PolicyFullUpdate",
    "PolicyResponse",
    "PolicyRuleCreate",
    "PolicyRuleMutationResponse",
    "PolicyRuleResponse",
]

from typing import Any, Literal

from pydantic import BaseModel


class PolicyResponse(BaseModel):
    """Policy response with metadata.

    Note: HITL configuration is now in AppConfig, not PolicyConfig.
    Use /api/config endpoint for HITL settings.
    """

    version: str
    default_action: str
    rules_count: int
    rules: list[dict[str, Any]]
    policy_version: str | None
    policy_path: str


class PolicyRuleResponse(BaseModel):
    """Single policy rule for API response."""

    id: str | None
    effect: str
    conditions: dict[str, Any]
    description: str | None


class PolicyRuleCreate(BaseModel):
    """Request body for creating/updating a rule."""

    id: str | None = None
    description: str | None = None
    effect: Literal["allow", "deny", "hitl"]
    conditions: dict[str, Any]


class PolicyRuleMutationResponse(BaseModel):
    """Response after creating/updating a rule."""

    rule: PolicyRuleResponse
    policy_version: str | None
    rules_count: int


class PolicyFullUpdate(BaseModel):
    """Request body for full policy update.

    Allows replacing the entire policy configuration including rules.
    Note: HITL configuration is now in AppConfig (config.json), not PolicyConfig.
    """

    version: str = "1"
    default_action: Literal["deny"] = "deny"
    rules: list[PolicyRuleCreate]
