# LinkedIn Launch Package: MCP Gateway

## Brand Direction

- Visual system: premium oriental editorial, ink wash, porcelain blue, rice paper, red seal.
- Voice: grounded, curious, build-first, no AI slop.
- Category: AI agent systems builder working on MCP security infrastructure.
- Avoid: hype claims, "revolutionary", "unlock", "the future is here", over-teaching from a pedestal.

## Post 1: Soft Build-In-Public Launch

I’ve been noticing something weird about AI agents:

Most people are still talking about prompts.

But once agents connect to real tools, the bigger question becomes:

What are they allowed to see?
What are they allowed to call?
What changed since the last time I trusted this tool?

I built a small local-first MCP gateway to explore that.

It sits between an AI client and MCP servers, then:

- scans tool descriptions for poisoned instructions
- blocks suspicious tool inputs
- rate-limits runaway tool calls
- detects descriptor drift after a first trusted baseline
- writes redacted audit logs

The part that made this click for me:

A malicious MCP tool does not always need to be called.

If its description gets loaded into the agent context, the damage can start before the user notices anything.

So the gateway blocks unsafe tool descriptions before the agent even sees them.

Still early. Still rough.

But this feels like the kind of infrastructure agents need if they’re going to move from demos into actual workflows.

Repo: https://github.com/Niraven/mcp-gateway

I’m still figuring out the exact product shape, but the lane is clear:

less agent hype, more agent control.

## Post 2: Carousel Caption - MCP Gateway Launch

I built a local-first firewall for MCP tool calls.

The idea is simple:

AI agents should not get raw, unfiltered access to every connected tool.

The gateway checks tool descriptions, tracks descriptor changes, blocks risky inputs, rate-limits calls, and writes audit logs.

This is still early, but the demo now proves the core behavior:

- poisoned tool descriptions are blocked before listing
- descriptor drift can be blocked after baseline
- shell-injection-like input gets stopped before execution
- audit logs are written with secret redaction

I’m sharing this as build-in-public proof, not a polished launch.

But I think this is the right direction:

agents need infrastructure, not just better prompts.

Repo: https://github.com/Niraven/mcp-gateway

## Post 3: Lessons Caption

A few things I learned building an MCP gateway:

1. Tool metadata is not harmless.

Agents read descriptions to decide how to use tools. That makes descriptions part of the attack surface.

2. Approval is not enough.

If a poisoned tool appears in context before approval, you may already have a problem.

3. Trust needs memory.

A tool can look safe today and change tomorrow. Descriptor hashing gives you a baseline.

4. Logs are a product feature.

If an agent touches real systems, you need to know what happened. And you need secrets redacted by default.

5. Local-first matters.

Developers should be able to test this before adopting a hosted platform.

This is the lane I’m exploring now:

AI agent security infrastructure.

Not more agent hype. More control around what agents can touch.

## Carousel 1: MCP Gateway Launch

Source files:

- `social/carousels/mcp-gateway-launch/mcp-gateway-launch.pdf`
- `social/carousels/mcp-gateway-launch/slide-01.svg`
- `social/carousels/mcp-gateway-launch/png/slide-01.png`

Recommended LinkedIn upload: use the PDF as a document carousel.

Fallback upload: use the PNGs in order as an image carousel.

## Carousel 2: Agent Security Lessons

Source files:

- `social/carousels/agent-security-lessons/agent-security-lessons.pdf`
- `social/carousels/agent-security-lessons/slide-01.svg`
- `social/carousels/agent-security-lessons/png/slide-01.png`

Recommended LinkedIn upload: use the PDF as a document carousel.

Fallback upload: use the PNGs in order as an image carousel.
