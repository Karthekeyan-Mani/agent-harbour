# Self-Fleet Attribution

## Overview

Agent Harbour supports self-fleet attribution to separate internal/team traffic from external agent traffic. This allows you to distinguish between your own agents (Jarvis, internal crawlers, verification tools) and real external AI agents discovering your service.

## Usage for Harbour Team

When making requests to Agent Harbour from internal tools, agents, or verification scripts, include the `X-Harbour-Self` header:

```bash
# Example: Jarvis agent checking the service
curl -H "X-Harbour-Self: jarvis" https://agent-harbour.fly.dev/agents

# Example: Internal verification probe
curl -H "X-Harbour-Self: verify-bot" https://agent-harbour.fly.dev/manifest

# Alternative: Use fleet header for general internal traffic
curl -H "X-Harbour-Fleet: grokbot" https://agent-harbour.fly.dev/
```

## Headers

### `X-Harbour-Self: <agent-slug>`

Identifies a specific internal agent by slug. The crawler will be recorded as `Self-<slug>` with operator `GrokBotFleet`.

- **Example**: `X-Harbour-Self: jarvis` → Recorded as `Self-jarvis` / `GrokBotFleet`
- **Allowed characters**: `a-zA-Z0-9_-` (max 50 chars, sanitized)
- **Rate Limit Benefit**: POST /api/register with this header gets 30/hour limit (vs 3/hour for public)

### `X-Harbour-Fleet: <fleet-name>`

Identifies general fleet traffic without a specific agent name. Accepted values: `grokbot`, `harbour`.

- **Example**: `X-Harbour-Fleet: grokbot` → Recorded as `Self-internal` / `GrokBotFleet`

## Sightings Filtering

Self-fleet traffic is **excluded by default** from public sightings endpoints and the homepage to avoid inflating external agent metrics.

### Public API

```bash
# Default: external agents only (excludes self-fleet)
GET /api/sightings

# Include self-fleet traffic
GET /api/sightings?include_self=true

# Include undeclared bots (excludes self-fleet)
GET /api/sightings?include_undeclared=true

# Include everything (self-fleet + undeclared)
GET /api/sightings?include_undeclared=true&include_self=true
```

## Implementation Details

Self-fleet attribution has the highest priority in crawler identification:

1. **Priority 1**: Self-fleet headers (`X-Harbour-Self`, `X-Harbour-Fleet`)
2. **Priority 2**: Ignore list (curl, wget, Cursor, Grok Bot UA strings)
3. **Priority 3**: Known crawlers (GPTBot, ClaudeBot, etc.)
4. **Priority 4**: Undeclared bot detection

## Security

- No raw IPs or full User-Agent strings are stored
- Self-fleet slugs are sanitized to prevent injection
- Only the crawler label and operator are recorded

## Why This Matters

External agents won't start registering in significant numbers until:
- **Wave B**: Directory listings and framework integrations drive discovery
- **Network effects**: Agents discover other agents through the public registry
- **Documentation spread**: More agents become aware of the register-on-read pattern

The radar measures real external interest; self-fleet separation prevents false signals during the early growth phase.
