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
from typing import TYPE_CHECKING, Any, Callable, NoReturn, assert_never

from fastmcp.server.middleware import Middleware
from fastmcp.server.middleware.middleware import CallNext, MiddlewareContext

from mcp.types import ListToolsResult

from mcp_acp_extended.context import ActionCategory, DecisionContext, build_decision_context
from mcp_acp_extended.pdp import Decision, MatchedRule, PolicyEngine
from mcp_acp_extended.exceptions import (
    AuthenticationError,
    PermissionDeniedError,
    SessionBindingViolationError,
)
from mcp_acp_extended.pep.approval_store import ApprovalStore
from mcp_acp_extended.api.routes.approvals import register_approval_store
from mcp_acp_extended.pep.hitl import HITLHandler, HITLOutcome
from mcp_acp_extended.pep.rate_handler import RateBreachHandler
from mcp_acp_extended.security.identity import IdentityProvider
from mcp_acp_extended.security.rate_limiter import SessionRateTracker
from mcp_acp_extended.security.tool_sanitizer import ToolListSanitizer
from mcp_acp_extended.utils.logging.extractors import extract_client_info
from mcp_acp_extended.telemetry.system.system_logger import get_system_logger
from mcp_acp_extended.telemetry.audit.decision_logger import create_decision_logger, DecisionEventLogger
from mcp_acp_extended.utils.logging.logging_context import get_request_id, get_session_id

if TYPE_CHECKING:
    from mcp_acp_extended.pdp.policy import PolicyConfig

_system_logger = get_system_logger()


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
        shutdown_callback: Callable[[str], None],
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
            shutdown_callback: Called for critical security failures (audit, session binding).
            policy_version: Policy version for audit logging.
            rate_tracker: Optional rate tracker for detecting runaway loops.
        """
        self._shutdown_callback = shutdown_callback
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
        # Tool description sanitizer for prompt injection defense
        self._tool_sanitizer = ToolListSanitizer(logger, _system_logger)
        # Decision event logger for audit trail
        self._decision_logger = DecisionEventLogger(
            logger=logger,
            system_logger=_system_logger,
            backend_id=backend_id,
            policy_version=policy_version,
        )
        # Rate breach handler (only if rate tracking enabled)
        self._rate_breach_handler: RateBreachHandler | None = None
        if rate_tracker is not None:
            self._rate_breach_handler = RateBreachHandler(
                hitl_handler=self._hitl_handler,
                rate_tracker=rate_tracker,
                decision_logger=self._decision_logger,
                system_logger=_system_logger,
                context_builder=self._build_context,
            )

    @property
    def approval_store(self) -> ApprovalStore:
        """Get the approval store for cache management."""
        return self._approval_store

    def reload_policy(self, new_policy: "PolicyConfig", policy_version: str | None = None) -> dict[str, int]:
        """Reload policy configuration for hot reload.

        Updates:
        - PolicyEngine's policy reference (atomic swap)
        - HITL handler config (for cache TTL changes)
        - RateBreachHandler's HITL handler reference
        - DecisionEventLogger's policy version
        - Clears approval cache (HITL rules may have changed)

        On error, rolls back to previous state to maintain consistency.

        Args:
            new_policy: New validated PolicyConfig to apply.
            policy_version: New policy version for audit logs (e.g., "v3").

        Returns:
            Dict with old_rules_count, new_rules_count, approvals_cleared.

        Raises:
            Exception: Re-raises any exception after rolling back state.
        """
        # Save old state for rollback
        old_policy = self._engine.policy
        old_hitl_handler = self._hitl_handler
        old_hitl_config = self._hitl_config
        old_approval_store = self._approval_store
        old_policy_version = self._decision_logger._policy_version
        old_count = len(old_policy.rules)

        try:
            # Swap policy in engine (atomic reference swap)
            self._engine.reload_policy(new_policy)

            # Update HITL handler and config (in case TTL or settings changed)
            self._hitl_handler = HITLHandler(new_policy.hitl)
            self._hitl_config = new_policy.hitl

            # Update RateBreachHandler's HITL reference (uses new timeout settings)
            if self._rate_breach_handler is not None:
                self._rate_breach_handler._hitl_handler = self._hitl_handler

            # Update DecisionEventLogger's policy version for audit trail
            self._decision_logger._policy_version = policy_version

            # Update approval store TTL if it changed
            if self._approval_store.ttl_seconds != new_policy.hitl.approval_ttl_seconds:
                # Create new store with new TTL (old approvals are cleared anyway)
                self._approval_store = ApprovalStore(ttl_seconds=new_policy.hitl.approval_ttl_seconds)
                register_approval_store(self._approval_store)
                cleared_count = 0  # New store, nothing to clear
            else:
                # Clear existing cache - HITL rules may have changed
                cleared_count = self._approval_store.clear()

            new_count = len(new_policy.rules)

            return {
                "old_rules_count": old_count,
                "new_rules_count": new_count,
                "approvals_cleared": cleared_count,
            }

        except Exception as e:
            # Rollback to previous state on any error (logged to system.jsonl)
            _system_logger.error(
                {
                    "event": "policy_reload_rollback",
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
            )
            self._engine.reload_policy(old_policy)
            self._hitl_handler = old_hitl_handler
            self._hitl_config = old_hitl_config
            # Rollback RateBreachHandler's HITL reference
            if self._rate_breach_handler is not None:
                self._rate_breach_handler._hitl_handler = old_hitl_handler
            # Rollback DecisionEventLogger's policy version
            self._decision_logger._policy_version = old_policy_version
            if self._approval_store is not old_approval_store:
                self._approval_store = old_approval_store
                register_approval_store(old_approval_store)
            raise

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

    def _get_matched_rules(self, decision_context: DecisionContext) -> tuple[list[MatchedRule], str]:
        """Get matched rules and final rule for logging.

        Collects all matching rules and determines which one was decisive
        based on the combining algorithm: HITL > DENY > ALLOW.

        Args:
            decision_context: Context used for evaluation.

        Returns:
            Tuple of (matched_rules, final_rule). Matched rules include
            id, effect, and description for decision trace logging.
        """
        # Check for built-in protected path (checked first in engine)
        path = decision_context.resource.resource.path if decision_context.resource.resource else None
        if self._engine.is_protected_path(path):
            return [], "built_in_protected_path"

        # Check for discovery bypass
        if decision_context.action.category == ActionCategory.DISCOVERY:
            return [], "discovery_bypass"

        # Use public API to get matching rules (includes id, effect, description)
        matching = self._engine.get_matching_rules(decision_context)

        if not matching:
            return [], "default"

        # Determine final rule using combining algorithm: HITL > DENY > ALLOW
        first_hitl = next((m.id for m in matching if m.effect == "hitl"), None)
        first_deny = next((m.id for m in matching if m.effect == "deny"), None)
        first_allow = next((m.id for m in matching if m.effect == "allow"), None)

        final_rule = first_hitl or first_deny or first_allow or "default"

        return matching, final_rule

    async def _handle_allow_decision(
        self,
        *,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any],
        decision_context: DecisionContext,
        matched_rules: list[MatchedRule],
        final_rule: str,
        eval_duration_ms: float,
        method: str,
        request_id: str,
        session_id: str,
    ) -> Any:
        """Handle ALLOW decision: log decision and forward request.

        Args:
            context: Middleware context.
            call_next: Next middleware in chain.
            decision_context: Context used for evaluation.
            matched_rules: List of matched rule IDs.
            final_rule: Rule that determined outcome.
            eval_duration_ms: Policy evaluation time.
            method: MCP method name.
            request_id: Request correlation ID.
            session_id: Session ID.

        Returns:
            Response from downstream middleware.
        """
        self._decision_logger.log(
            decision=Decision.ALLOW,
            decision_context=decision_context,
            matched_rules=matched_rules,
            final_rule=final_rule,
            policy_eval_ms=eval_duration_ms,
        )
        result = await call_next(context)

        # Sanitize tools/list responses to protect against prompt injection
        if method == "tools/list":
            if isinstance(result, ListToolsResult):
                try:
                    result = self._tool_sanitizer.sanitize(result, request_id, session_id)
                except Exception as e:
                    # Fail-open: return unsanitized rather than failing the request
                    _system_logger.error(
                        {
                            "event": "sanitization_failed",
                            "message": f"Failed to sanitize tools/list response: {e}",
                            "error_type": type(e).__name__,
                            "request_id": request_id,
                            "session_id": session_id,
                        }
                    )
            else:
                # Unexpected result type - log warning
                _system_logger.warning(
                    {
                        "event": "sanitization_skipped",
                        "message": f"tools/list returned unexpected type: {type(result).__name__}",
                        "result_type": type(result).__name__,
                        "request_id": request_id,
                        "session_id": session_id,
                    }
                )

        return result

    def _handle_deny_decision(
        self,
        *,
        decision_context: DecisionContext,
        matched_rules: list[MatchedRule],
        final_rule: str,
        eval_duration_ms: float,
        method: str,
    ) -> NoReturn:
        """Handle DENY decision: log and raise PermissionDeniedError.

        Args:
            decision_context: Context used for evaluation.
            matched_rules: Matched rules with id, effect, description.
            final_rule: Rule that determined outcome.
            eval_duration_ms: Policy evaluation time.
            method: MCP method name.

        Raises:
            PermissionDeniedError: Always raised.
        """
        self._decision_logger.log(
            decision=Decision.DENY,
            decision_context=decision_context,
            matched_rules=matched_rules,
            final_rule=final_rule,
            policy_eval_ms=eval_duration_ms,
        )

        tool_name = decision_context.resource.tool.name if decision_context.resource.tool else None
        path = decision_context.resource.resource.path if decision_context.resource.resource else None

        raise PermissionDeniedError(
            f"Policy denied: {method}" + (f" on {path}" if path else ""),
            decision=Decision.DENY,
            tool_name=tool_name,
            path=path,
            matched_rules=[r.id for r in matched_rules],
            final_rule=final_rule,
        )

    async def _handle_hitl_decision(
        self,
        *,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any],
        decision_context: DecisionContext,
        matched_rules: list[MatchedRule],
        final_rule: str,
        eval_duration_ms: float,
        method: str,
        request_id: str,
    ) -> Any:
        """Handle HITL decision: check cache, show dialog, enforce result.

        Args:
            context: Middleware context.
            call_next: Next middleware in chain.
            decision_context: Context used for evaluation.
            matched_rules: Matched rules with id, effect, description.
            final_rule: Rule that determined outcome.
            eval_duration_ms: Policy evaluation time.
            method: MCP method name.
            request_id: Request correlation ID.

        Returns:
            Response from downstream if user approves.

        Raises:
            PermissionDeniedError: If user denies or times out.
        """
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
            self._decision_logger.log(
                decision=Decision.HITL,
                decision_context=decision_context,
                hitl_outcome=HITLOutcome.USER_ALLOWED,
                hitl_cache_hit=True,
                matched_rules=matched_rules,
                final_rule=final_rule,
                policy_eval_ms=eval_duration_ms,
                policy_hitl_ms=0.0,  # No wait time - used cache
            )
            return await call_next(context)

        # No cached approval - show dialog
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

            # Log and allow
            self._decision_logger.log(
                decision=Decision.HITL,
                decision_context=decision_context,
                hitl_outcome=hitl_result.outcome,
                hitl_cache_hit=False,  # User was prompted
                matched_rules=matched_rules,
                final_rule=final_rule,
                policy_eval_ms=eval_duration_ms,
                policy_hitl_ms=hitl_result.response_time_ms,
            )
            return await call_next(context)

        # User denied or timeout - log and deny
        self._decision_logger.log(
            decision=Decision.HITL,
            decision_context=decision_context,
            hitl_outcome=hitl_result.outcome,
            hitl_cache_hit=False,  # User was prompted
            matched_rules=matched_rules,
            final_rule=final_rule,
            policy_eval_ms=eval_duration_ms,
            policy_hitl_ms=hitl_result.response_time_ms,
        )

        reason = "User denied" if hitl_result.outcome == HITLOutcome.USER_DENIED else "Approval timeout"
        raise PermissionDeniedError(
            f"{reason}: {method}" + (f" on {path}" if path else ""),
            decision=Decision.HITL,
            tool_name=tool_name,
            path=path,
            matched_rules=[r.id for r in matched_rules],
            final_rule=final_rule,
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
        if self._rate_breach_handler and method == "tools/call":
            tool_name = arguments.get("name") if arguments else None
            if tool_name:
                rate_allowed, rate_count = self._rate_tracker.check(session_id, tool_name)
                if not rate_allowed:
                    # Rate limit exceeded - trigger HITL
                    # If user approves, continues to policy evaluation below
                    # If user denies, raises PermissionDeniedError
                    await self._rate_breach_handler.handle(
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
        except AuthenticationError as e:
            # Authentication failed - surface the actual message so user knows to re-login
            _system_logger.error(
                {
                    "event": "authentication_failed",
                    "message": str(e),
                    "method": method,
                    "request_id": request_id,
                    "session_id": session_id,
                }
            )
            raise PermissionDeniedError(
                str(e),  # Surface actual message: "Not authenticated. Run 'auth login'..."
                decision=Decision.DENY,
            ) from e
        except SessionBindingViolationError as e:
            # Critical security event - identity changed mid-session
            # Trigger shutdown immediately - this is a potential session hijacking attempt
            _system_logger.critical(
                {
                    "event": "session_binding_violation",
                    "error": str(e),
                    "method": method,
                    "request_id": request_id,
                    "session_id": session_id,
                    "message": "Identity changed mid-session - triggering shutdown",
                }
            )
            self._shutdown_callback(str(e))
            raise
        except Exception as e:
            # Other errors - generic message (fail-secure, don't leak details)
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
            return await self._handle_allow_decision(
                context=context,
                call_next=call_next,
                decision_context=decision_context,
                matched_rules=matched_rules,
                final_rule=final_rule,
                eval_duration_ms=eval_duration_ms,
                method=method,
                request_id=request_id,
                session_id=session_id,
            )

        elif decision == Decision.DENY:
            self._handle_deny_decision(
                decision_context=decision_context,
                matched_rules=matched_rules,
                final_rule=final_rule,
                eval_duration_ms=eval_duration_ms,
                method=method,
            )

        elif decision == Decision.HITL:
            return await self._handle_hitl_decision(
                context=context,
                call_next=call_next,
                decision_context=decision_context,
                matched_rules=matched_rules,
                final_rule=final_rule,
                eval_duration_ms=eval_duration_ms,
                method=method,
                request_id=request_id,
            )

        # Should never reach here - all Decision enum values are handled above
        assert_never(decision)


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
        shutdown_callback=shutdown_callback,
        policy_version=policy_version,
        rate_tracker=rate_tracker,
    )
