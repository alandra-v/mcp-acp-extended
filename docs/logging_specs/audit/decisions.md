### ABAC decisions

The policy decision log schema records the outcome of attribute-based access control (ABAC) evaluations performed by the proxy for each Model Context Protocol request. Each entry captures the evaluated action, the identified subject and backend, the final rule responsible for the decision, and the set of matched rules that contributed to the outcome, providing transparency into why a request was allowed, denied, or escalated. For high-risk operations, the schema additionally supports synchronous human-in-the-loop (HITL) enforcement by logging the human approval or denial outcome and the associated response time. By correlating each decision with the corresponding session, request, and active policy version, the decision log enables auditability, policy analysis, and forensic reconstruction of authorization behavior in a zero-trust proxy environment.

## Core
time — ISO 8601 timestamp (added by formatter during serialization)
event — fixed string "policy_decision"

## Decision outcome
decision — "allow" | "deny" | "hitl"
matched_rules — list of all rule IDs that matched (can be empty)
final_rule — rule that determined the outcome (or "default", "discovery_bypass", "built_in_protected_path")

## Context summary
mcp_method — MCP method ("tools/call", "resources/read", etc.)
tool_name — optional, only for tools/call
path — optional file path (from tool arguments)
uri — optional resource URI (from resources/read)
scheme — optional URI scheme (file, https, s3, etc.)
subject_id — optional, OIDC sub (optional until auth is fully implemented)
backend_id — backend server ID (always known from config)
is_mutating — whether the action is mutating (default: false)
side_effects — optional list of side-effect tags (e.g. "fs_read", "fs_write")

## Policy
policy_version — active policy version at decision time (always loaded)

## Performance
policy_eval_ms — policy rule evaluation time in milliseconds
policy_hitl_ms — optional, HITL wait time in milliseconds (only when decision == "hitl")
policy_total_ms — total evaluation time in milliseconds (eval + HITL, excludes context)

## Correlation
request_id — JSON-RPC request ID (every decision has a request)
session_id — optional, MCP session ID (may not exist during initialize)

## HITL (only when decision == "hitl")
hitl_outcome — "user_allowed" | "user_denied" | "timeout"
