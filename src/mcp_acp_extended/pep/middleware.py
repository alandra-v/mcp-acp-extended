"""Policy Enforcement Point (PEP) middleware.

Intercepts MCP requests, evaluates policy, and enforces decisions.
Logs every decision to audit/decisions.jsonl.

Middleware order: Context (outer) → Audit → ClientLogger → Enforcement (inner)
- Context is outermost: sets request_id, session_id, tool_context for all others
- Enforcement is innermost: blocks requests before they reach the backend
- All logging middleware sees denials because enforcement raises through them
"""

from __future__ import annotations

__all__ = [
    "PolicyEnforcementMiddleware",
    "create_enforcement_middleware",
]

import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, NoReturn

from fastmcp.server.middleware import Middleware
from fastmcp.server.middleware.middleware import CallNext, MiddlewareContext

from mcp.shared.exceptions import McpError
from mcp.types import ErrorData, INTERNAL_ERROR

from mcp_acp_extended.context import ActionCategory, DecisionContext, build_decision_context
from mcp_acp_extended.pdp import Decision, PolicyEngine
from mcp_acp_extended.exceptions import PermissionDeniedError
from mcp_acp_extended.pep.approval_store import ApprovalStore
from mcp_acp_extended.api.routes.approvals import register_approval_store
from mcp_acp_extended.pep.hitl import HITLHandler, HITLOutcome
from mcp_acp_extended.security.identity import IdentityProvider
from mcp_acp_extended.security.rate_limiter import SessionRateTracker
from mcp_acp_extended.security.integrity.emergency_audit import log_with_fallback
from mcp_acp_extended.utils.logging.extractors import extract_client_info
from mcp_acp_extended.telemetry.models.decision import DecisionEvent
from mcp_acp_extended.telemetry.system.system_logger import get_system_logger
from mcp_acp_extended.telemetry.audit.decision_logger import create_decision_logger
from mcp_acp_extended.utils.logging.logging_context import get_request_id, get_session_id

if TYPE_CHECKING:
    from mcp_acp_extended.pdp.policy import PolicyConfig

_system_logger = get_system_logger()


def _assert_never(value: NoReturn) -> NoReturn:
    """Assert that a code path is never reached.

    Used for exhaustive pattern matching - the type checker will warn
    if not all enum values are handled before this is called.

    Args:
        value: The value that should never exist.

    Raises:
        AssertionError: Always raised if this code is reached.
    """
    raise AssertionError(f"Unexpected value: {value!r}")


class PolicyEnforcementMiddleware(Middleware):
    """Middleware that enforces policy decisions on MCP requests.

    Intercepts every request, builds decision context, evaluates policy,
    and either allows the request through or blocks it.

    For HITL decisions, shows approval dialog and waits for user response.

    Logs every decision (including discovery bypasses) to decisions.jsonl.
    """

    def __init__(
        self,
        *,
        policy: "PolicyConfig",
        protected_dirs: tuple[str, ...],
        identity_provider: IdentityProvider,
        backend_id: str,
        logger: logging.Logger,
        policy_version: str | None = None,
        rate_tracker: SessionRateTracker | None = None,
    ) -> None:
        """Initialize enforcement middleware.

        Args:
            policy: Policy configuration to enforce.
            protected_dirs: Directories protected from MCP tool access (config, logs).
            identity_provider: Provider for user identity.
            backend_id: Backend server ID (from config.backend.server_name).
            logger: Logger for decision events.
            policy_version: Policy version for audit logging.
            rate_tracker: Optional rate tracker for detecting runaway loops.
        """
        self._engine = PolicyEngine(policy, protected_dirs=protected_dirs)
        self._identity_provider = identity_provider
        self._backend_id = backend_id
        self._logger = logger
        self._policy_version = policy_version
        self._hitl_handler = HITLHandler(policy.hitl)
        self._hitl_config = policy.hitl  # For cache settings
        # Approval cache for reducing HITL dialog fatigue
        self._approval_store = ApprovalStore(ttl_seconds=policy.hitl.approval_ttl_seconds)
        # Register with API for debugging visibility
        register_approval_store(self._approval_store)
        # Client name extracted from initialize request
        self._client_name: str | None = None
        # Rate limiting for detecting runaway loops
        self._rate_tracker = rate_tracker

    @property
    def approval_store(self) -> ApprovalStore:
        """Get the approval store for cache management."""
        return self._approval_store

    def _extract_client_name(self, context: MiddlewareContext[Any]) -> None:
        """Extract and cache client name from initialize request.

        Args:
            context: Middleware context.
        """
        if self._client_name is not None:
            return

        client_info = extract_client_info(context)
        if client_info.name:
            self._client_name = client_info.name

    async def _build_context(
        self,
        method: str,
        arguments: dict[str, Any] | None,
        request_id: str,
        session_id: str,
    ) -> DecisionContext:
        """Build decision context for policy evaluation.

        Args:
            method: MCP method name.
            arguments: Request arguments.
            request_id: Request correlation ID.
            session_id: Session ID.

        Returns:
            DecisionContext for policy evaluation.
        """
        return await build_decision_context(
            method=method,
            arguments=arguments,
            identity_provider=self._identity_provider,
            session_id=session_id,
            request_id=request_id,
            backend_id=self._backend_id,
            client_name=self._client_name,
        )

    def _extract_arguments(self, context: MiddlewareContext[Any]) -> dict[str, Any] | None:
        """Extract request arguments from middleware context.

        In FastMCP, context.message IS the params object (e.g., CallToolRequestParams),
        not a wrapper with a .params attribute.

        Args:
            context: Middleware context.

        Returns:
            Arguments dict or None.
        """
        try:
            message = context.message
            if message is None:
                return None

            # context.message IS the params object directly (e.g., CallToolRequestParams)
            if hasattr(message, "model_dump"):
                result: dict[str, Any] = message.model_dump()
                return result
            elif hasattr(message, "__dict__"):
                return dict(message.__dict__)
        except (AttributeError, TypeError):
            pass
        return None

    def _log_decision(
        self,
        decision: Decision,
        decision_context: DecisionContext,
        matched_rules: list[str],
        final_rule: str,
        policy_eval_ms: float,
        hitl_outcome: HITLOutcome | None = None,
        policy_hitl_ms: float | None = None,
        hitl_cache_hit: bool | None = None,
    ) -> None:
        """Log policy decision to decisions.jsonl with fallback chain.

        Uses fallback chain: decisions.jsonl -> system.jsonl -> emergency_audit.jsonl.
        If primary logging fails, logs to fallbacks and raises McpError.

        Args:
            decision: The policy decision.
            decision_context: Context used for evaluation.
            matched_rules: List of rule IDs that matched.
            final_rule: Rule that determined outcome.
            policy_eval_ms: Policy rule evaluation time.
            hitl_outcome: HITL outcome if applicable.
            policy_hitl_ms: HITL wait time if applicable.
            hitl_cache_hit: True if approval from cache, False if user prompted.

        Raises:
            McpError: If primary logging fails (after logging to fallbacks).
        """
        # Extract context summary
        tool = decision_context.resource.tool
        resource = decision_context.resource.resource

        tool_name = tool.name if tool else None
        path = resource.path if resource else None
        uri = resource.uri if resource else None
        scheme = resource.scheme if resource else None

        # Extract side effects as list of strings
        side_effects: list[str] | None = None
        if tool and tool.side_effects:
            side_effects = [effect.value for effect in tool.side_effects]

        # Calculate total time (eval + HITL, excludes context)
        policy_total_ms = policy_eval_ms + (policy_hitl_ms or 0.0)

        # Map USER_ALLOWED_ONCE to user_allowed for logging (same outcome, different caching)
        hitl_outcome_value: str | None = None
        if hitl_outcome:
            if hitl_outcome == HITLOutcome.USER_ALLOWED_ONCE:
                hitl_outcome_value = "user_allowed"
            else:
                hitl_outcome_value = hitl_outcome.value

        event = DecisionEvent(
            decision=decision.value,
            matched_rules=matched_rules,
            final_rule=final_rule,
            mcp_method=decision_context.action.mcp_method,
            tool_name=tool_name,
            path=path,
            uri=uri,
            scheme=scheme,
            subject_id=decision_context.subject.id,
            backend_id=self._backend_id,
            side_effects=side_effects,
            policy_version=self._policy_version or "unknown",
            policy_eval_ms=round(policy_eval_ms, 2),
            policy_hitl_ms=round(policy_hitl_ms, 2) if policy_hitl_ms else None,
            policy_total_ms=round(policy_total_ms, 2),
            request_id=decision_context.environment.request_id,
            session_id=decision_context.environment.session_id,
            hitl_outcome=hitl_outcome_value,
            hitl_cache_hit=hitl_cache_hit,
        )

        # Log with fallback chain
        event_data = event.model_dump(exclude={"time"}, exclude_none=True)
        success, failure_reason = log_with_fallback(
            primary_logger=self._logger,
            system_logger=_system_logger,
            event_data=event_data,
            event_type="decision",
            source_file="decisions.jsonl",
        )

        # If primary audit failed, raise error to client before shutdown
        if not success:
            raise McpError(
                ErrorData(
                    code=INTERNAL_ERROR,
                    message="Decision audit log failure - logged to fallback, proxy shutting down",
                )
            )

    def _get_matched_rules(self, decision_context: DecisionContext) -> tuple[list[str], str]:
        """Get matched rules and final rule for logging.

        Collects all matching rules and determines which one was decisive
        based on the combining algorithm: HITL > DENY > ALLOW.

        Args:
            decision_context: Context used for evaluation.

        Returns:
            Tuple of (matched_rule_ids, final_rule).
        """
        # Check for built-in protected path (checked first in engine)
        path = decision_context.resource.resource.path if decision_context.resource.resource else None
        if self._engine.is_protected_path(path):
            return [], "built_in_protected_path"

        # Check for discovery bypass
        if decision_context.action.category == ActionCategory.DISCOVERY:
            return [], "discovery_bypass"

        # Use public API to get matching rules
        matching = self._engine.get_matching_rules(decision_context)

        if not matching:
            return [], "default"

        # Extract rule IDs
        matched_rules = [m.id for m in matching]

        # Determine final rule using combining algorithm: HITL > DENY > ALLOW
        first_hitl = next((m.id for m in matching if m.effect == "hitl"), None)
        first_deny = next((m.id for m in matching if m.effect == "deny"), None)
        first_allow = next((m.id for m in matching if m.effect == "allow"), None)

        final_rule = first_hitl or first_deny or first_allow or "default"

        return matched_rules, final_rule

    async def _handle_rate_breach(
        self,
        *,
        tool_name: str,
        rate_count: int,
        threshold: int,
        session_id: str,
        request_id: str,
    ) -> None:
        """Handle rate limit breach by triggering HITL.

        If user approves, returns normally so caller can continue with policy evaluation.
        If user denies or times out, raises PermissionDeniedError.

        Args:
            tool_name: Tool that exceeded rate limit.
            rate_count: Current call count in window.
            threshold: Threshold that was exceeded.
            session_id: Session identifier.
            request_id: Request identifier.

        Raises:
            PermissionDeniedError: If user denied or timeout.
        """
        _system_logger.warning(
            {
                "event": "rate_limit_exceeded",
                "message": f"Rate limit exceeded for {tool_name}: {rate_count}/{threshold} calls",
                "tool_name": tool_name,
                "count": rate_count,
                "threshold": threshold,
                "session_id": session_id,
                "request_id": request_id,
            }
        )

        # Show HITL dialog for rate breach
        # Build a minimal decision context for the dialog
        try:
            decision_context = await self._build_context(
                method="tools/call",
                arguments={"name": tool_name},
                request_id=request_id,
                session_id=session_id,
            )
        except Exception:
            # If context building fails, deny by default
            raise PermissionDeniedError(
                f"Rate limit exceeded: {rate_count} calls to {tool_name} in {int(self._rate_tracker.window_seconds)}s",
                decision=Decision.DENY,
                tool_name=tool_name,
                matched_rules=["rate_limit"],
                final_rule="rate_limit_breach",
            )

        # Show approval dialog
        hitl_result = await self._hitl_handler.request_approval(
            decision_context,
            matched_rule="rate_limit_breach",
            will_cache=False,  # Never cache rate limit approvals
        )

        if hitl_result.outcome in (HITLOutcome.USER_ALLOWED, HITLOutcome.USER_ALLOWED_ONCE):
            # User allowed - reset rate counter to avoid immediate re-trigger
            self._rate_tracker.reset_tool(session_id, tool_name)

            # Log to decisions.jsonl for audit trail
            self._log_decision(
                decision=Decision.ALLOW,  # User override
                decision_context=decision_context,
                matched_rules=["rate_limit_breach"],
                final_rule="rate_limit_breach",
                policy_eval_ms=0.0,  # No policy eval - rate limit check
                hitl_outcome=hitl_result.outcome,
                policy_hitl_ms=hitl_result.response_time_ms,
                hitl_cache_hit=False,  # Rate limits never cached
            )

            _system_logger.info(
                {
                    "event": "rate_limit_approved",
                    "message": f"User approved rate limit breach for {tool_name}",
                    "tool_name": tool_name,
                    "count": rate_count,
                    "hitl_outcome": hitl_result.outcome.value,
                    "session_id": session_id,
                    "request_id": request_id,
                }
            )
            # Return normally - caller will continue with policy evaluation
            return
        else:
            # User denied or timeout
            reason = "User denied" if hitl_result.outcome == HITLOutcome.USER_DENIED else "Approval timeout"

            # Log to decisions.jsonl for audit trail
            self._log_decision(
                decision=Decision.DENY,
                decision_context=decision_context,
                matched_rules=["rate_limit_breach"],
                final_rule="rate_limit_breach",
                policy_eval_ms=0.0,  # No policy eval - rate limit check
                hitl_outcome=hitl_result.outcome,
                policy_hitl_ms=hitl_result.response_time_ms,
                hitl_cache_hit=False,  # Rate limits never cached
            )

            _system_logger.info(
                {
                    "event": "rate_limit_denied",
                    "message": f"{reason} for rate limit breach on {tool_name}",
                    "tool_name": tool_name,
                    "count": rate_count,
                    "hitl_outcome": hitl_result.outcome.value,
                    "session_id": session_id,
                    "request_id": request_id,
                }
            )
            raise PermissionDeniedError(
                f"{reason}: Rate limit exceeded ({rate_count} calls to {tool_name})",
                decision=Decision.DENY,
                tool_name=tool_name,
                matched_rules=["rate_limit"],
                final_rule="rate_limit_breach",
            )

    async def on_message(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any],
    ) -> Any:
        """Process message through policy enforcement.

        Evaluates policy and either allows request through or blocks it.

        Args:
            context: Middleware context containing request.
            call_next: Next middleware in chain.

        Returns:
            Response from downstream if allowed.

        Raises:
            PermissionDeniedError: If policy denies the request, context
                building fails, or HITL approval is denied/times out.
        """
        # Extract client name from initialize (cached for session)
        self._extract_client_name(context)

        # Get correlation IDs
        request_id = get_request_id() or "unknown"
        session_id = get_session_id() or "unknown"

        # Extract arguments
        arguments = self._extract_arguments(context)
        method = context.method or "unknown"

        # Rate limiting check (before policy evaluation for efficiency)
        if self._rate_tracker and method == "tools/call":
            tool_name = arguments.get("name") if arguments else None
            if tool_name:
                rate_allowed, rate_count = self._rate_tracker.check(session_id, tool_name)
                if not rate_allowed:
                    # Rate limit exceeded - trigger HITL
                    # If user approves, continues to policy evaluation below
                    # If user denies, raises PermissionDeniedError
                    await self._handle_rate_breach(
                        tool_name=tool_name,
                        rate_count=rate_count,
                        threshold=self._rate_tracker.per_tool_thresholds.get(
                            tool_name, self._rate_tracker.default_threshold
                        ),
                        session_id=session_id,
                        request_id=request_id,
                    )

        # Build decision context
        try:
            decision_context = await self._build_context(method, arguments, request_id, session_id)
        except Exception as e:
            # Log error and deny by default (fail-secure)
            _system_logger.error(
                {
                    "event": "context_build_error",
                    "message": f"Failed to build decision context: {e}",
                    "error_type": type(e).__name__,
                    "method": method,
                    "request_id": request_id,
                    "session_id": session_id,
                }
            )
            raise PermissionDeniedError(
                f"Internal error evaluating policy for {method}",
                decision=Decision.DENY,
            ) from e

        # Evaluate policy
        eval_start = time.perf_counter()
        decision = self._engine.evaluate(decision_context)
        eval_duration_ms = (time.perf_counter() - eval_start) * 1000

        # Get matched rules for logging
        matched_rules, final_rule = self._get_matched_rules(decision_context)

        # Handle decision
        if decision == Decision.ALLOW:
            # Log and allow
            self._log_decision(
                decision=decision,
                decision_context=decision_context,
                matched_rules=matched_rules,
                final_rule=final_rule,
                policy_eval_ms=eval_duration_ms,
            )
            return await call_next(context)

        elif decision == Decision.DENY:
            # Log and deny
            self._log_decision(
                decision=decision,
                decision_context=decision_context,
                matched_rules=matched_rules,
                final_rule=final_rule,
                policy_eval_ms=eval_duration_ms,
            )

            tool_name = decision_context.resource.tool.name if decision_context.resource.tool else None
            path = decision_context.resource.resource.path if decision_context.resource.resource else None

            raise PermissionDeniedError(
                f"Policy denied: {method}" + (f" on {path}" if path else ""),
                decision=decision,
                tool_name=tool_name,
                path=path,
                matched_rules=matched_rules,
                final_rule=final_rule,
            )

        elif decision == Decision.HITL:
            # Extract context for caching
            tool = decision_context.resource.tool
            tool_name = tool.name if tool else None
            path = decision_context.resource.resource.path if decision_context.resource.resource else None
            subject_id = decision_context.subject.id

            # Determine if this tool's approval can be cached (for dialog buttons)
            tool_side_effects = tool.side_effects if tool else None
            will_cache = ApprovalStore.should_cache(
                tool_side_effects=tool_side_effects,
                allowed_effects=self._hitl_config.cache_side_effects,
            )

            # Check approval cache first (reduces HITL dialog fatigue)
            cached_approval = self._approval_store.lookup(
                subject_id=subject_id,
                tool_name=tool_name or "unknown",
                path=path,
            )

            if cached_approval is not None:
                # Cached approval found - skip dialog and allow
                cache_age_s = self._approval_store.get_age_seconds(cached_approval)
                _system_logger.debug(
                    {
                        "event": "hitl_cache_hit",
                        "message": f"Using cached approval for {tool_name}",
                        "tool_name": tool_name,
                        "path": path,
                        "subject_id": subject_id,
                        "cache_age_s": round(cache_age_s, 1),
                        "original_request_id": cached_approval.request_id,
                        "request_id": request_id,
                    }
                )
                self._log_decision(
                    decision=decision,
                    decision_context=decision_context,
                    matched_rules=matched_rules,
                    final_rule=final_rule,
                    policy_eval_ms=eval_duration_ms,
                    hitl_outcome=HITLOutcome.USER_ALLOWED,
                    policy_hitl_ms=0.0,  # No wait time - used cache
                    hitl_cache_hit=True,
                )
                return await call_next(context)

            # No cached approval - show dialog
            # Pass will_cache so dialog shows appropriate buttons
            hitl_result = await self._hitl_handler.request_approval(
                decision_context,
                matched_rule=final_rule,
                will_cache=will_cache,
            )

            if hitl_result.outcome in (HITLOutcome.USER_ALLOWED, HITLOutcome.USER_ALLOWED_ONCE):
                # User approved - cache only if USER_ALLOWED (not USER_ALLOWED_ONCE)
                if hitl_result.outcome == HITLOutcome.USER_ALLOWED and will_cache:
                    self._approval_store.store(
                        subject_id=subject_id,
                        tool_name=tool_name or "unknown",
                        path=path,
                        request_id=request_id,
                    )
                    _system_logger.debug(
                        {
                            "event": "hitl_approval_cached",
                            "message": f"Cached approval for {tool_name}",
                            "tool_name": tool_name,
                            "path": path,
                            "subject_id": subject_id,
                            "ttl_seconds": self._hitl_config.approval_ttl_seconds,
                            "request_id": request_id,
                        }
                    )

                # Log and allow
                self._log_decision(
                    decision=decision,
                    decision_context=decision_context,
                    matched_rules=matched_rules,
                    final_rule=final_rule,
                    policy_eval_ms=eval_duration_ms,
                    hitl_outcome=hitl_result.outcome,
                    policy_hitl_ms=hitl_result.response_time_ms,
                    hitl_cache_hit=False,  # User was prompted
                )
                return await call_next(context)
            else:
                # User denied or timeout - log and deny
                self._log_decision(
                    decision=decision,
                    decision_context=decision_context,
                    matched_rules=matched_rules,
                    final_rule=final_rule,
                    policy_eval_ms=eval_duration_ms,
                    hitl_outcome=hitl_result.outcome,
                    policy_hitl_ms=hitl_result.response_time_ms,
                    hitl_cache_hit=False,  # User was prompted
                )

                reason = (
                    "User denied" if hitl_result.outcome == HITLOutcome.USER_DENIED else "Approval timeout"
                )
                raise PermissionDeniedError(
                    f"{reason}: {method}" + (f" on {path}" if path else ""),
                    decision=decision,
                    tool_name=tool_name,
                    path=path,
                    matched_rules=matched_rules,
                    final_rule=final_rule,
                )

        # Should never reach here - all Decision enum values are handled above
        _assert_never(decision)


def create_enforcement_middleware(
    *,
    policy: "PolicyConfig",
    protected_dirs: tuple[str, ...],
    identity_provider: IdentityProvider,
    backend_id: str,
    log_path: Path,
    shutdown_callback: Callable[[str], None],
    policy_version: str | None = None,
    rate_tracker: SessionRateTracker | None = None,
) -> PolicyEnforcementMiddleware:
    """Create policy enforcement middleware.

    Factory function for creating enforcement middleware with fail-closed
    decision logging. If the decisions.jsonl audit log is compromised,
    the shutdown callback is invoked.

    Args:
        policy: Policy configuration to enforce.
        protected_dirs: Directories protected from MCP tool access (config, logs).
        identity_provider: Provider for user identity.
        backend_id: Backend server ID.
        log_path: Path to decisions.jsonl file.
        shutdown_callback: Called if audit log integrity check fails.
        policy_version: Policy version for audit logging (e.g., "v1").
        rate_tracker: Optional rate tracker for detecting runaway loops.

    Returns:
        Configured PolicyEnforcementMiddleware.
    """
    logger = create_decision_logger(log_path, shutdown_callback)

    return PolicyEnforcementMiddleware(
        policy=policy,
        protected_dirs=protected_dirs,
        identity_provider=identity_provider,
        backend_id=backend_id,
        logger=logger,
        policy_version=policy_version,
        rate_tracker=rate_tracker,
    )
