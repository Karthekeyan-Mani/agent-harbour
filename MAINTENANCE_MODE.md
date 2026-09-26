# Maintenance Mode Operations Guide

## Quick Reference

**Enable maintenance mode:**
```bash
fly secrets set MAINTENANCE_MODE=1 -a agent-harbour
```

**Disable maintenance mode:**
```bash
fly secrets unset MAINTENANCE_MODE -a agent-harbour
```

**Check current status:**
```bash
fly secrets list -a agent-harbour | grep MAINTENANCE_MODE
```

## How It Works

When `MAINTENANCE_MODE` is enabled:

### Browser/HTML Routes
- **Returns:** HTTP 503 with maintenance HTML page
- **Message:** "Harbour Closed - Temporary Maintenance"
- **Includes:** `Retry-After: 3600` header (1 hour)
- **Affects:** Home, leaderboard, and all user-facing pages

### API/Machine Routes
- **Returns:** HTTP 503 with JSON response
- **Format:** `{"error": "Service Unavailable", "message": "...", "maintenance": true}`
- **Includes:** `Retry-After: 3600` header
- **Affects:** `/api/*`, `/.well-known/*`, `/openapi*`, `/mcp`, `/agents`, `/manifest`

### Health Checks
- **Returns:** HTTP 200 OK (normal response)
- **Reason:** Keeps Fly.io health checks passing so the machine isn't terminated
- **Path:** `/health`

## Accepted Values (Case-Insensitive)

**Truthy (enables maintenance):** `1`, `true`, `yes`, `on`

**Falsy (disables maintenance):** `0`, `false`, `no`, `off`, `disabled`, empty, or unset

## Testing Locally

```bash
# Start with maintenance mode enabled
DATABASE_PATH="/tmp/test.db" MAINTENANCE_MODE=1 \
  uvicorn app.main:app --host 127.0.0.1 --port 8080

# Visit http://127.0.0.1:8080 - should see maintenance page
# Visit http://127.0.0.1:8080/health - should see {"status": "ok"}
```

## Production Deployment

Changes take effect **immediately** when setting or unsetting the secret - no redeploy required.

### Typical Workflow

1. **Before maintenance:**
   ```bash
   fly secrets set MAINTENANCE_MODE=1 -a agent-harbour
   # Wait a few seconds for it to take effect
   curl -I https://agent-harbour.fly.dev/
   # Should return 503
   ```

2. **Perform maintenance work** (deploy updates, database migrations, etc.)

3. **After maintenance:**
   ```bash
   fly secrets unset MAINTENANCE_MODE -a agent-harbour
   # Wait a few seconds
   curl -I https://agent-harbour.fly.dev/
   # Should return 200
   ```

## Implementation Details

- **Middleware:** `maintenance_mode_middleware` in `app/main.py` (line ~661)
- **Runs first:** Before the `contact_radar` middleware
- **Default:** OFF (no behavior change without the env var)
- **Tests:** `test_maintenance_mode.py` (full coverage)

## Troubleshooting

**Q: The site is still responding normally after setting MAINTENANCE_MODE**
- Wait 10-15 seconds for the secret to propagate
- Verify the secret is set: `fly secrets list -a agent-harbour`
- Check logs: `fly logs -a agent-harbour`

**Q: Health checks are failing**
- The `/health` endpoint should always return 200, even in maintenance mode
- If failing, there's a different issue - check logs

**Q: How do I test without affecting production?**
- Run locally with `MAINTENANCE_MODE=1` set in your shell
- Or use a staging Fly.io app
