# Agent Black Hole — Cloudflare Worker Sensor

This Cloudflare Worker detects AI agent and crawler visits to your site and reports them to your Agent Black Hole (Harbour) instance.

**Privacy-first:** No IP addresses are stored. Only crawler labels, paths, and timestamps.

## Quick Start

### 1. Create a Site in Harbour

First, register your site with your Harbour instance:

```bash
curl -X POST https://agent-harbour.fly.dev/api/sites \
  -H "Content-Type: application/json" \
  -d '{"name":"My Documentation Site"}'
```

You'll receive a response like:

```json
{
  "site_id": 1,
  "name": "My Documentation Site",
  "ingest_key": "abc123...",
  "warning": "Store this ingest key securely. It will not be shown again.",
  "ingest_url": "https://agent-harbour.fly.dev/api/sites/1/sightings",
  "dashboard_url": "https://agent-harbour.fly.dev/sites/1"
}
```

**Important:** Save the `ingest_key` securely. You cannot retrieve it later.

### 2. Deploy to Cloudflare

#### Option A: Using Wrangler CLI

1. Install Wrangler:
   ```bash
   npm install -g wrangler
   ```

2. Create a new Worker project:
   ```bash
   wrangler init agent-sensor
   cd agent-sensor
   ```

3. Copy `cloudflare-worker.js` to `src/index.js`

4. Configure `wrangler.toml`:
   ```toml
   name = "agent-sensor"
   main = "src/index.js"
   compatibility_date = "2024-01-01"
   
   [env.production]
   vars = { HARBOUR_URL = "https://agent-harbour.fly.dev", HARBOUR_SITE_ID = "1" }
   ```

5. Set the secret ingest key:
   ```bash
   wrangler secret put HARBOUR_INGEST_KEY
   # Paste your ingest key when prompted
   ```

6. Deploy:
   ```bash
   wrangler deploy
   ```

#### Option B: Using Cloudflare Dashboard

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Go to **Workers & Pages** → **Create application** → **Create Worker**
3. Name it (e.g., "agent-sensor")
4. Click **Deploy**, then **Edit code**
5. Copy the contents of `cloudflare-worker.js` and paste it
6. Click **Save and Deploy**
7. Go to **Settings** → **Variables**
8. Add environment variables:
   - `HARBOUR_URL` = `https://agent-harbour.fly.dev` (or your Harbour URL)
   - `HARBOUR_SITE_ID` = your site ID (e.g., `1`)
9. Add a secret:
   - `HARBOUR_INGEST_KEY` = your ingest key (encrypted)

### 3. Add Route to Your Site

1. In Cloudflare Dashboard, go to your website's **Workers Routes**
2. Click **Add route**
3. Set route pattern: `*yourdomain.com/*`
4. Select your worker: `agent-sensor`
5. Save

Now all requests to your site will pass through the sensor!

## View Your Dashboard

Visit your site's dashboard using the URL from step 1:

```
https://agent-harbour.fly.dev/sites/{your-site-id}
```

You'll need to include the ingest key as a Bearer token:

```bash
curl https://agent-harbour.fly.dev/sites/1 \
  -H "Authorization: Bearer YOUR_INGEST_KEY"
```

Or in your browser, you can create a simple bookmarklet or extension to inject the auth header.

## API Endpoints

### Get Sightings (JSON)

```bash
curl https://agent-harbour.fly.dev/api/sites/{site_id}/sightings \
  -H "Authorization: Bearer YOUR_INGEST_KEY"
```

Returns:

```json
{
  "site_id": 1,
  "sightings": [
    {
      "crawler_label": "GPTBot",
      "operator_label": "OpenAI",
      "path": "/docs/api",
      "first_seen": "2026-09-18T01:30:00Z",
      "last_seen": "2026-09-18T01:45:00Z",
      "hit_count": 3
    }
  ]
}
```

## Customization

### Sample Requests

By default, the sensor reports every crawler visit. To sample (e.g., 10% of requests):

```javascript
if (crawler) {
  if (Math.random() < 0.1) {  // 10% sampling
    ctx.waitUntil(reportSighting(env, path, crawler));
  }
}
```

### Filter Paths

To only track certain paths:

```javascript
if (crawler && path.startsWith('/docs')) {
  ctx.waitUntil(reportSighting(env, path, crawler));
}
```

### Custom Response

The default worker passes requests through to your origin. You can customize the response:

```javascript
// Return a custom response for crawlers
if (crawler) {
  ctx.waitUntil(reportSighting(env, path, crawler));
  return new Response('Hello, ' + crawler.label + '!', {
    headers: { 'Content-Type': 'text/plain' }
  });
}

// Normal requests
return fetch(request);
```

## Privacy & Security

- **No IP addresses** are stored or transmitted
- **No raw User-Agent strings** are persisted (only mapped to known crawler labels)
- **Query strings are stripped** from paths to avoid leaking sensitive parameters
- Ingest keys are hashed on the server and should be kept secret
- Rate limiting is applied to prevent abuse

## Troubleshooting

### No sightings appearing

1. Check that your worker is deployed and the route is active
2. Verify environment variables are set correctly
3. Check browser console or `wrangler tail` for errors:
   ```bash
   wrangler tail agent-sensor
   ```

### Authentication errors

1. Verify your `HARBOUR_INGEST_KEY` secret is set correctly
2. Try regenerating a new site and ingest key
3. Check that `HARBOUR_SITE_ID` matches your site

### Want to test locally?

```bash
# Visit a page as a crawler
curl -A "GPTBot/1.0" http://localhost:8787/test

# Check worker logs
wrangler tail agent-sensor --format pretty
```

## Support

- Main documentation: https://agent-harbour.fly.dev/sensor
- Harbour rules: https://agent-harbour.fly.dev/harbour-rules
- Report issues: Create an issue in the repository

## What Gets Detected?

The sensor recognizes these crawlers out of the box:

- OpenAI (GPTBot, ChatGPT-User, OAI-SearchBot)
- Anthropic (ClaudeBot, Claude-Web, Claude-User, Anthropic-AI)
- Google (Google-Extended, GoogleBot-AI, GeminiBot)
- Perplexity (PerplexityBot, Perplexity-User)
- Meta (Meta-ExternalAgent, FacebookBot, Meta-ExternalFetcher)
- ByteDance (Bytespider)
- Others: Amazonbot, CCBot, Cohere-AI, Diffbot, YouBot, PetalBot, Applebot(-Extended), Grok, DeepSeek

Unknown bots with `bot/`, `crawler/`, or `spider/` patterns are labeled as `UndeclaredBot`.

Development tools (curl, wget, Postman, etc.) are **not** tracked.
