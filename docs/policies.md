# Policies

## Overview

Policies define what operations are allowed, denied, or require human approval.

- **Default action**: Explicit DENY (zero trust)
- **Glob patterns**: Path matching with `*`, `**`, `?`
- **Operations**: read, write, delete (inferred from tool names - see caveat below)
- **Effects**: allow, deny, hitl (human-in-the-loop)
- **Fully configurable**: Users define their own rules

---

## How Policy Evaluation Works

```
┌────────────────────┐
│ Subject Attributes ├──┐
└────────────────────┘  │
┌────────────────────┐  │    ┌───────────────┐
│ Resource Attributes├──┼───►│ Policy Engine ├───► ALLOW / DENY / HITL
└────────────────────┘  │    └───────────────┘
┌────────────────────┐  │
│ Action Attributes  ├──┤
└────────────────────┘  │
┌────────────────────┐  │
│ Env Attributes     ├──┘
└────────────────────┘
```

```
1. MCP request arrives at proxy
2. Context is built from request (ABAC attributes)
3. Policy engine evaluates rules against context
4. Decision returned: ALLOW, DENY, or HITL
5. Decision enforced and logged
```

### Context Building (ABAC Model)

The proxy builds a `DecisionContext` with four attribute categories:

| Category | Attributes | Source |
|----------|------------|--------|
| **Subject** | `user_id`, `hostname`, `client_name` | Local identity provider |
| **Action** | `mcp_method`, `intent`, `category` | MCP request |
| **Resource** | `tool_name`, `path`, `extension`, `backend_id`, `side_effects` | MCP request arguments |
| **Environment** | `timestamp`, `session_id`, `request_id` | Runtime context |

**No external PIPs**: Currently all context is built from local information (request data, config). No external Policy Information Points (IdP, tool registry, threat feeds) are queried. Future versions may add external PIPs.

### Policy Engine

Rules are evaluated against the context:
1. Collect all rules where conditions match the context
2. Apply combining algorithm: **HITL > DENY > ALLOW** (most restrictive wins)
3. If no rules match → `default_action` (DENY)

**Fail-closed**: Any error in context building or policy evaluation results in DENY.

---

## Policy File Structure

```json
{
  "version": "1",
  "default_action": "deny",
  "rules": [
    { "id": "allow-reads", "effect": "allow", "conditions": { "operations": ["read"] } },
    { "id": "hitl-writes", "effect": "hitl", "conditions": { "operations": ["write"] } }
  ],
  "hitl": { "timeout_seconds": 30 }
}
```

---

## Rule Conditions

All conditions in a rule use **AND logic** (all must match):

| Condition | Description | Matching |
|-----------|-------------|----------|
| `tool_name` | Tool name pattern | glob, case-insensitive |
| `path_pattern` | File path pattern | glob with ** |
| `operations` | Operation types | read/write/delete |
| `extension` | File extension | case-insensitive |
| `scheme` | URL scheme | case-insensitive |
| `backend_id` | Server identifier | case-insensitive |
| `resource_type` | Resource type | |
| `mcp_method` | MCP method name | case-sensitive |
| `subject_id` | User identity | case-sensitive |
| `side_effects` | Side effect types | ANY logic |

**Empty conditions are invalid** (rejected by validator - would match everything).

---

## Operation Inference

Operations (read/write/delete) are inferred from tool name patterns (`read_*`, `write_*`, etc.).

**This is a HEURISTIC, not a security guarantee** - tool names may lie.

- Unknown tools with operation conditions -> rule doesn't match (safe default)

---

## Side Effects System

The side effects system allows policies to match based on what a tool CAN DO rather than just its name.

### Available Side Effects

| Category | Side Effects |
|----------|--------------|
| Filesystem | `fs_read`, `fs_write` |
| Database | `db_read`, `db_write` |
| Network | `network_egress`, `network_ingress` |
| Execution | `code_exec`, `process_spawn`, `sudo_elevate` |
| Secrets | `secrets_read`, `env_read`, `keychain_read` |
| System | `clipboard_read`, `clipboard_write`, `browser_open` |
| Capture | `screen_capture`, `audio_capture`, `camera_capture` |
| Cloud | `cloud_api`, `container_exec` |
| Communication | `email_send` |

### Side Effects Matching

Uses **ANY logic**: matches if tool has ANY of the listed effects.

Unknown tools have empty side effects -> won't match side_effect rules (conservative).

### How Side Effects Are Determined

Side effects are currently **manually mapped** per tool. Example mappings:

| Tool | Side Effects |
|------|--------------|
| `bash` | `code_exec`, `fs_write`, `fs_read`, `network_egress`, `process_spawn` |
| `read_file` | `fs_read` |
| `write_file` | `fs_write` |

### Important Limitations

| Limitation | Implication |
|------------|-------------|
| **Manual mapping** | Side effects are DECLARED, not detected or verified yet |
| **Tool names can lie** | A malicious tool named `read_file` could actually execute code |
| **Unknown tools have no effects** | Tools not in mapping won't match side_effect policy rules |
| **No runtime verification** | We don't analyze what a tool actually does |

### Trust Model

- We currently trust that tool names are honest (weak assumption)
- The mapping is based on common tool naming conventions
- Unknown tools fail-safe: they won't match allow rules with side_effect conditions

Future: Verified Tool Registry

---

## Discovery Bypass

These methods skip policy evaluation entirely:
- `initialize`, `ping` - connection setup
- `tools/list`, `resources/list`, `prompts/list` - capability discovery
- `notifications/*` - async notifications

**`prompts/get` is NOT bypassed** - it returns actual content and needs policy evaluation.

Logged as `discovery_bypass` in decision logs for audit trail.

### Why Discovery Methods Bypass Policy

| Reason | Explanation |
|--------|-------------|
| **Protocol requirement** | MCP clients MUST call `initialize` and discovery methods to function. Denying these breaks the protocol entirely. |
| **No state mutation** | These methods don't change anything - they only return metadata about capabilities. |
| **No sensitive data** | Discovery returns tool names/descriptions, not actual content. |
| **Defense in depth** | Even if an attacker sees what tools exist, they can't USE them without policy approval. |
| **Audit trail preserved** | All discovery calls are logged with `final_rule: "discovery_bypass"`. |

**Exception: `prompts/get`** returns actual prompt content which could contain:
- Sensitive instructions
- API keys embedded in prompts
- Business logic that shouldn't be exposed

Therefore `prompts/get` requires policy evaluation like any other action.

---

## Example Policy

A practical policy allowing reads, requiring approval for writes to project directory:

```json
{
  "version": "1",
  "default_action": "deny",
  "rules": [
    {
      "id": "allow-read-project",
      "effect": "allow",
      "conditions": {
        "tool_name": "read*",
        "path_pattern": "<test-workspace>/**"
      }
    },
    {
      "id": "hitl-write-project",
      "effect": "hitl",
      "conditions": {
        "tool_name": "write*",
        "path_pattern": "<workspace>/**"
      }
    },
    {
      "id": "deny-secrets-dir",
      "effect": "deny",
      "conditions": {
        "path_pattern": "**/secrets/**"
      }
    },
    {
      "id": "deny-private-dir",
      "effect": "deny",
      "conditions": {
        "path_pattern": "**/private/**"
      }
    }
  ],
  "hitl": {
    "timeout_seconds": 30,
    "default_on_timeout": "deny"
  }
}
```

**How this works:**
- Reads: allowed everywhere
- Writes to `/Users/*/Projects/**`: HITL approval required
- Writes elsewhere: denied (rule order matters - more specific rules first)
- Deletes: denied everywhere

---

## Human-in-the-Loop (HITL)

HITL is triggered **exclusively by policy rules** with `effect: "hitl"`. The system does not yet perform autonomous context analysis, heuristic-based triggering, or risk scoring.

### Platform Support

Currently **macOS only** via native `osascript` dialogs:
- GUI popup with "Allow" / "Deny" buttons
- **Return/Enter** → Allow, **Escape** → Deny
- Audio notification (`Funk.aiff`) on first dialog
- Queue indicator shows pending requests

**Linux/Windows**: Auto-deny with warning log. Cross-platform UI planned.

### Dialog Content

```
Tool: <tool_name>
Path: <path>                    (truncated to 60 chars if needed)
Rule: <rule_that_triggered>     (why HITL was required)
Effects: <side_effects>         (e.g., fs_write, code_exec)
User: <subject_id>
Queue: #2 pending               (only shown if queue_position > 1)

Auto-deny in 30s
[Return] Allow  *  [Esc] Deny
```

### Timeout Configuration

- Default: 30 seconds, range: 5-300 seconds
- Configurable in `policy.json`:
  ```json
  "hitl": { "timeout_seconds": 60 }
  ```

**Note**: MCP clients have their own request timeouts. Ensure client timeout > HITL timeout to allow user response time.

### Audit & Security

All HITL decisions are logged to `decisions.jsonl`. See [Logging](logging.md) for details and [Security](security.md) for HITL security design decisions.

### Future Possibilities (Not Implemented)

| Future Capability | Description |
|-------------------|-------------|
| Risk-based HITL | Score requests and trigger HITL above threshold |
| Anomaly detection | Detect unusual patterns (burst access, odd hours) |
| Content inspection | Trigger HITL if secrets/PII detected in request |
| Approval state | Re-trigger HITL if previous approval expired |

---

### Policy DSL Migration Path (Cedar/Rego)

The current JSON policy format is explicitly designed for future migration to a proper policy DSL.

**Current policy model maps to:**

| Current JSON | Cedar Equivalent | Rego Equivalent |
|--------------|------------------|-----------------|
| `effect: "allow"` | `permit` | `allow = true` |
| `effect: "deny"` | `forbid` | `deny = true` |
| `effect: "hitl"` | Custom action (Cedar doesn't have HITL) | `hitl = true` |
| `conditions.tool_name` | `resource.tool_name == "..."` | `input.resource.tool_name == "..."` |
| `conditions.path_pattern` | `resource.path like "..."` | `glob.match(pattern, [], input.resource.path)` |
| `conditions.operations` | `action in [Action::"read", ...]` | `input.action.intent == allowed[_]` |
| `conditions.side_effects` | `resource.side_effects.contains(...)` | `input.resource.side_effects[_] == ...` |
| `default_action: "deny"` | Implicit (no match = deny) | `default allow = false` |

**Why current AND-only is migration-safe:**

```
Current JSON (AND logic):
{ "conditions": { "tool_name": "bash", "path_pattern": "/tmp/**" } }

→ Cedar:
permit(principal, action, resource)
when { resource.tool_name == "bash" && resource.path like "/tmp/*" };

→ Rego:
allow {
    input.resource.tool_name == "bash"
    glob.match("/tmp/**", [], input.resource.path)
}
```

**Adding OR would complicate migration:**

```
Hypothetical OR JSON:
{ "or": [{ "tool_name": "bash" }, { "tool_name": "shell" }] }

→ Must translate to:
allow { input.resource.tool.name == "bash" }
allow { input.resource.tool.name == "shell" }  # Rego: multiple rule heads = OR
```

This is still expressible, but nested AND/OR/NOT creates complex AST translation.

**Recommendation for OR support:**

Instead of full boolean logic, add **condition-level alternatives**:

```json
{
  "conditions": {
    "tool_name": ["bash", "shell"],  // Array = OR (match any)
    "path_pattern": "/tmp/**"         // Still AND with other conditions
  }
}
```

This translates cleanly:
```rego
allow {
    input.resource.tool_name == ["bash", "shell"][_]  # Rego: array iteration = OR
    glob.match("/tmp/**", [], input.resource.path)
}
```

**When to migrate:**
- When policy complexity exceeds what JSON can express readably
- When policy testing/simulation tools are needed (Cedar Playground, Rego Playground)
- When static analysis is needed (Cedar Analyzer, Rego type checking)
- When policy authoring is by security team, not developers



## See Also

- [Configuration](configuration.md) for policy file location
- [Security](security.md) for fail-closed behavior
- [Logging](logging.md) for decision logging
