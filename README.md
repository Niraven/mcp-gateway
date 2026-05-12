# mcp-gateway

[![npm version](https://img.shields.io/npm/v/mcp-gateway)](https://www.npmjs.com/package/mcp-gateway)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

**Security-first gateway proxy for MCP servers.** Rate limiting, audit logging, real-time security scanning, and human approval workflows for every AI tool call.

---

## The Problem

AI agents call MCP tools autonomously. Without a gateway:

- An agent can spam tools thousands of times per minute
- Destructive operations (delete, push, drop) execute without confirmation
- Tool inputs with shell injection or path traversal pass through unchecked
- Poisoned tool descriptions hijack agent behavior silently
- You have zero visibility into what was called, when, or why

## Quick Start

```bash
# 1. Generate config
npx mcp-gateway init > mcp-gateway.json

# 2. Edit config (add your servers)
vim mcp-gateway.json

# 3. Start the proxy
npx mcp-gateway start -c mcp-gateway.json
```

Your AI client connects to the gateway. The gateway connects to your servers. Every call goes through the policy engine.

## Architecture

```
  AI Client (Claude Desktop / Cursor / VS Code)
                      |
                      | stdio (MCP protocol)
                      |
              ┌───────────────┐
              │  mcp-gateway  │
              │               │
              │  rate limit   │
              │  scan inputs  │
              │  check descs  │
              │  audit log    │
              │  approve/deny │
              └───────┬───────┘
                      |
          ┌───────────┼───────────┐
          |           |           |
    ┌─────────┐ ┌─────────┐ ┌─────────┐
    │filesys  │ │ github  │ │database │
    └─────────┘ └─────────┘ └─────────┘
```

## Configuration

```json
{
  "servers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "./project"]
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}" }
    }
  },
  "policies": {
    "rateLimit": {
      "maxCallsPerMinute": 30,
      "maxCallsPerHour": 500,
      "perTool": {
        "write_file": { "maxCallsPerMinute": 5 },
        "delete_file": { "maxCallsPerMinute": 2 }
      }
    },
    "approval": {
      "requireApprovalFor": [
        { "type": "destructive" },
        { "type": "pattern", "match": "delete|drop|push" }
      ],
      "approvalTimeout": 30000,
      "defaultAction": "deny"
    },
    "security": {
      "blockOnCritical": true,
      "blockOnHigh": true,
      "scanDescriptions": true,
      "scanInputs": true
    }
  },
  "audit": {
    "enabled": true,
    "logPath": "./mcp-audit.jsonl",
    "includeArgs": true
  }
}
```

## Features

### Rate Limiting

Per-tool and global rate limits with sliding window enforcement. Prevents runaway agents from exhausting API quotas.

```
[BLOCKED by mcp-gateway] Rate limit exceeded: 6/5 calls/min for write_file
```

### Security Scanning

Real-time detection of:
- Shell injection characters in tool inputs (`;&|`$`)
- Path traversal attempts (`../../etc/passwd`)
- XSS payloads in arguments
- Tool description poisoning (hidden instructions, concealment directives)
- Zero-width characters and invisible text in metadata

### Human Approval Gate

Require explicit human approval before destructive operations execute:
- Triggered by tool annotations (`destructiveHint: true`)
- Triggered by tool name patterns (regex)
- Configurable timeout with deny-by-default

### Audit Logging

Every tool call logged in JSONL:

```json
{
  "timestamp": "2025-01-15T10:30:00.000Z",
  "server": "filesystem",
  "tool": "write_file",
  "action": "allowed",
  "duration": 45,
  "findings": []
}
```

### Web Dashboard

Built-in monitoring panel showing live audit feed, rate limit status, security alerts, and server health.

```bash
mcp-gateway dashboard -c mcp-gateway.json -p 3100
# Open http://localhost:3100
```

## CLI

```bash
mcp-gateway start [-c config.json] [-v]   # Start the proxy
mcp-gateway dashboard [-c config.json]     # Start monitoring dashboard
mcp-gateway init                           # Generate sample config
mcp-gateway validate config.json           # Validate config
```

## Use with Claude Desktop

In your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "gateway": {
      "command": "npx",
      "args": ["mcp-gateway", "start", "-c", "/path/to/mcp-gateway.json"]
    }
  }
}
```

All upstream servers are now accessed through the gateway with full policy enforcement.

## Programmatic API

```typescript
import { McpGateway } from "mcp-gateway";

const gateway = new McpGateway({
  servers: { /* ... */ },
  policies: { /* ... */ },
  audit: { enabled: true }
});

await gateway.start();
```

## Why Not...

| | mcp-gateway | No gateway | trabecc |
|---|---|---|---|
| Rate limiting | Per-tool + global | None | Basic |
| Security scanning | Input + description | None | None |
| Tool poisoning detection | Yes | None | None |
| Approval workflows | Configurable | None | None |
| Audit logging | JSONL + dashboard | None | Basic |
| Web dashboard | Built-in | N/A | None |
| Architecture | Stdio proxy | N/A | HTTP proxy |
| Multiplexing | Built-in | N/A | Built-in |

## Roadmap

- [ ] SSE/HTTP transport support
- [ ] Per-server policy overrides
- [ ] Plugin system for custom middleware
- [ ] Token usage tracking
- [ ] Alert webhooks (Slack, Discord)

## License

MIT
