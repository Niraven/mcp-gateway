# MCP Gateway Run Report

Generated: 2026-05-13T01:08:38.998Z
Public mode: yes

## Summary

- Total tool calls: 5
- Malformed audit lines: 0
- First event: 2026-05-13T00:00:00.000Z
- Last event: 2026-05-13T00:00:08.000Z
- Risky-looking tool calls: 3
- Changed files from diff: 2

## Actions

| Action | Count |
|---|---:|
| allowed | 2 |
| pending-approval | 1 |
| blocked | 1 |
| rate-limited | 1 |

## Top Tools

| Tool | Calls |
|---|---:|
| read_file | 1 |
| write_file | 1 |
| push_changes | 1 |
| drop_table | 1 |
| search_nodes | 1 |

## Risks

- **MEDIUM risky-tool-allowed:** Risky-looking tool was allowed: filesystem.write_file. Evidence: Tool name matches destructive or externally visible action patterns.
- **MEDIUM tool-pending-approval:** github.push_changes was pending-approval. Evidence: Destructive tool requires approval
- **HIGH tool-blocked:** database.drop_table was blocked. Evidence: High severity security finding in tool call
- **HIGH input-shell-chars:** Suspicious shell-like characters in input Evidence: database.drop_table
- **MEDIUM tool-rate-limited:** memory.search_nodes was rate-limited. Evidence: Rate limit exceeded
- **LOW audit-args-enabled:** Audit logging includes tool arguments. Evidence: Use --public reports or disable includeArgs for sensitive environments.
- **MEDIUM descriptor-baseline-missing:** Descriptor baseline could not be read. Evidence: .mcp-gateway-descriptors.json

## Reliability Score

Conservative score: **17/20**
Known-evidence score: **17/18**

| Category | Score | Status | Evidence |
|---|---:|---|---|
| Goal clarity | 2 | scored | Run metadata includes a goal. |
| Tool permissions | 2 | scored | Gateway config was available for policy inspection. |
| Memory source | unknown | unknown | MCP audit logs do not expose memory-source quality. |
| Output contract | 2 | scored | Run metadata includes an output contract. |
| Eval/rubric | 2 | scored | Run metadata includes an eval/rubric. |
| Observability | 2 | scored | Scored from audit entries and audit config. |
| Recovery path | 2 | scored | Scored from approval, block, and rate-limit evidence. |
| Human handoff | 2 | scored | Approval policy exists. |
| Cost budget | 2 | scored | Rate limits are configured. |
| Privacy boundary | 1 | scored | Arguments are logged; public reports redact them. |

## Inputs

- Audit: sample-audit.jsonl
- Config: sample-config.json
- Descriptor baseline: not provided
- Diff: sample-run.diff
- Metadata: sample-metadata.json
