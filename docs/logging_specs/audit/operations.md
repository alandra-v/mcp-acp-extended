### API Activity [6003] Class
Application Activity Category

The schema follows the same conceptual structure as OCSF API Activity (actor, action, resource, outcome, time, duration) but uses a project-specific field naming.

## Core
time – ISO 8601 timestamp (added by formatter during serialization)
session_id – ID of the MCP session
request_id – per-MCP operation ID (JSON-RPC id)
method – MCP method, e.g. "tools/call", "tools/list", "resources/read", etc.
status – "Success" | "Failure"
error_code – MCP/JSON-RPC error code (optional, on failure)
message – short human-readable description (optional)

## Identity (from OIDC)
subject_id – the OIDC sub claim (required)
subject_claims – optional dict of selected safe claims (e.g. preferred_username, email)

## Client/Backend
client_id – MCP client application name (optional)
backend_id – internal ID of the MCP backend / server
transport – "stdio" or "streamablehttp" (optional)

## MCP operation details
tool_name – optional, only set if method == "tools/call" (e.g. "read_file")
file_path – optional, file path from request arguments
file_extension – optional, file extension (e.g. ".py", ".txt")
arguments_summary – optional object:
  redacted – bool (true, full args not logged)
  body_hash – SHA256 hex hash of the args (optional)
  payload_length – size in bytes of the request payload (optional)

## Response metadata
response_summary – optional object:
  size_bytes – response payload size in bytes
  body_hash – SHA256 hash of response payload

## Config
config_version – version string from your loaded config

## Duration
duration – required object:
  duration_ms – total operation duration in milliseconds (required)
