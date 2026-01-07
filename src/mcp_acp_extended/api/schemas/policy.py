"""Policy API schemas."""

from __future__ import annotations

__all__ = [
    "PolicyResponse",
    "PolicyRuleCreate",
    "PolicyRuleMutationResponse",
    "PolicyRuleResponse",
]

from typing import Any, Literal

from pydantic import BaseModel


class PolicyResponse(BaseModel):
    """Policy response with metadata."""

    version: str
    default_action: str
    rules_count: int
    rules: list[dict[str, Any]]
    hitl: dict[str, Any]
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
