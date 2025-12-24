"""Policy models for ABAC policy evaluation.

This module defines the policy schema used by the policy engine.
Designed for DSL compatibility (future Cedar/Rego migration).

Policy structure:
    PolicyConfig
    ├── version: Schema version for migrations
    ├── default_action: "deny" (zero trust)
    ├── rules: List[PolicyRule]
    │   └── PolicyRule
    │       ├── id: Optional identifier
    │       ├── effect: "allow" | "deny" | "hitl"
    │       └── conditions: RuleConditions (AND logic)
    └── hitl: HITLConfig
        ├── timeout_seconds
        └── default_on_timeout

Design principles:
1. All conditions use AND logic (all must match)
2. Deny-overrides combining: HITL > DENY > ALLOW
3. Default to DENY if no rule matches (zero trust)
4. DSL-compatible structure for future migration
"""

from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mcp_acp_extended.constants import (
    DEFAULT_HITL_TIMEOUT_SECONDS,
    MAX_HITL_TIMEOUT_SECONDS,
    MIN_HITL_TIMEOUT_SECONDS,
)
from mcp_acp_extended.context.resource import SideEffect


class RuleConditions(BaseModel):
    """Conditions for a policy rule (AND logic - all must match).

    At least one condition MUST be specified. Empty conditions are not allowed
    as they would match everything, which is a security risk.

    Attributes:
        tool_name: Tool name pattern (glob: *, ?) - case-insensitive
        path_pattern: Glob pattern for file paths (*, **, ?)
        operations: List of operations to match (read, write, delete)
        extension: Exact file extension match (e.g., ".key", ".env")
        scheme: Exact URI scheme match (e.g., "file", "db", "s3")
        backend_id: Server ID pattern (glob: *, ?) - case-insensitive
        resource_type: Exact resource type ("tool", "resource", "prompt", "server")
        mcp_method: MCP method pattern (glob: *, ?) e.g., "resources/*"
        subject_id: Exact subject/user ID match
        side_effects: Tool must have ANY of these side effects
    """

    # Original conditions
    tool_name: str | None = None
    path_pattern: str | None = None
    operations: list[Literal["read", "write", "delete"]] | None = None

    # New resource conditions
    extension: str | None = None
    scheme: str | None = None
    backend_id: str | None = None
    resource_type: Literal["tool", "resource", "prompt", "server"] | None = None

    # Action conditions
    mcp_method: str | None = None

    # Subject conditions
    subject_id: str | None = None

    # Side effects (ANY logic - matches if tool has any of the listed effects)
    side_effects: list[SideEffect] | None = None

    model_config = ConfigDict(frozen=True)

    @model_validator(mode="after")
    def at_least_one_condition(self) -> Self:
        """Validate that at least one condition is specified.

        Empty conditions would match everything, which is a security risk.
        """
        all_none = all(
            v is None
            for v in [
                self.tool_name,
                self.path_pattern,
                self.operations,
                self.extension,
                self.scheme,
                self.backend_id,
                self.resource_type,
                self.mcp_method,
                self.subject_id,
                self.side_effects,
            ]
        )
        if all_none:
            raise ValueError(
                "At least one condition must be specified. " "Empty conditions would match everything."
            )
        return self


class PolicyRule(BaseModel):
    """A single policy rule.

    All matching rules are collected and combined: HITL > DENY > ALLOW.
    All conditions use AND logic (all specified conditions must match).

    Attributes:
        id: Optional identifier for logging/debugging
        effect: What happens when rule matches
        conditions: Matching criteria (AND logic)
    """

    id: str | None = None
    effect: Literal["allow", "deny", "hitl"]
    conditions: RuleConditions = Field(default_factory=RuleConditions)

    model_config = ConfigDict(frozen=True)


class HITLConfig(BaseModel):
    """Configuration for Human-in-the-Loop approval.

    Attributes:
        timeout_seconds: How long to wait for user response (default: 30s).
            Must be between 5-300 seconds.
        default_on_timeout: What to do if user doesn't respond (always "deny").

    Important:
        The timeout should be shorter than your MCP client's request timeout.
        If the client times out before the user responds, the request will fail
        even if the user later approves. See constants.py for details.
    """

    timeout_seconds: int = Field(
        default=DEFAULT_HITL_TIMEOUT_SECONDS,
        ge=MIN_HITL_TIMEOUT_SECONDS,
        le=MAX_HITL_TIMEOUT_SECONDS,
    )
    default_on_timeout: Literal["deny"] = "deny"

    model_config = ConfigDict(frozen=True)


class PolicyConfig(BaseModel):
    """Complete policy configuration.

    Attributes:
        version: Schema version for migrations
        default_action: What to do when no rule matches (always "deny")
        rules: List of rules; all matches combined via HITL > DENY > ALLOW
        hitl: HITL configuration
    """

    version: str = "1"
    default_action: Literal["deny"] = "deny"
    rules: list[PolicyRule] = Field(default_factory=list)
    hitl: HITLConfig = Field(default_factory=HITLConfig)

    model_config = ConfigDict(frozen=True)


def create_default_policy() -> PolicyConfig:
    """Create a default policy with zero trust defaults.

    Returns:
        PolicyConfig with empty rules and deny default.
        Discovery methods bypass policy entirely (handled in engine).
    """
    return PolicyConfig(
        version="1",
        default_action="deny",
        rules=[],
        hitl=HITLConfig(),
    )
