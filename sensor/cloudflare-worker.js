/**
 * Agent Black Hole — Cloudflare Worker Sensor
 * 
 * Detects AI agent/crawler visits and reports them to your Harbour site.
 * Privacy-first: NO IP storage, only crawler labels + paths + timestamps.
 * 
 * Installation:
 * 1. Create a site at your Harbour instance: POST /api/sites
 * 2. Copy your site_id and ingest_key
 * 3. Set Cloudflare Worker environment variables:
 *    - HARBOUR_URL: Your Harbour instance URL (e.g. https://agent-harbour.fly.dev)
 *    - HARBOUR_SITE_ID: Your site ID
 *    - HARBOUR_INGEST_KEY: Your ingest key (secret)
 * 4. Deploy this worker to your Cloudflare zone
 */

// Known crawler patterns (mirrors Harbour's CRAWLERS)
const CRAWLERS = {
  'gptbot': { label: 'GPTBot', operator: 'OpenAI' },
  'chatgpt-user': { label: 'ChatGPT-User', operator: 'OpenAI' },
  'claudebot': { label: 'ClaudeBot', operator: 'Anthropic' },
  'claude-web': { label: 'Claude-Web', operator: 'Anthropic' },
  'perplexitybot': { label: 'PerplexityBot', operator: 'Perplexity' },
  'google-extended': { label: 'Google-Extended', operator: 'Google' },
  'googlebot-ai': { label: 'GoogleBot-AI', operator: 'Google' },
  'bytespider': { label: 'Bytespider', operator: 'ByteDance' },
  'cohere-ai': { label: 'Cohere-AI', operator: 'Cohere' },
  'ccbot': { label: 'CCBot', operator: 'Common Crawl' },
  'amazonbot': { label: 'Amazonbot', operator: 'Amazon' },
  'meta-externalagent': { label: 'Meta-ExternalAgent', operator: 'Meta' },
  'facebookbot': { label: 'FacebookBot', operator: 'Meta' },
  'applebot-extended': { label: 'Applebot-Extended', operator: 'Apple' },
  'anthropic-ai': { label: 'Anthropic-AI', operator: 'Anthropic' },
  'perplexity-user': { label: 'Perplexity-User', operator: 'Perplexity' },
  'claude-user': { label: 'Claude-User', operator: 'Anthropic' },
  'oai-searchbot': { label: 'OAI-SearchBot', operator: 'OpenAI' },
  'diffbot': { label: 'Diffbot', operator: 'Diffbot' },
  'youbot': { label: 'YouBot', operator: 'You.com' },
  'petalbot': { label: 'PetalBot', operator: 'Huawei' },
  'meta-externalfetcher': { label: 'Meta-ExternalFetcher', operator: 'Meta' },
  'applebot': { label: 'Applebot', operator: 'Apple' },
  'geminibot': { label: 'GeminiBot', operator: 'Google' },
  'grok': { label: 'Grok', operator: 'xAI' },
  'deepseek': { label: 'DeepSeek', operator: 'DeepSeek' },
};

// Tools to ignore (not crawlers)
const IGNORE_PATTERNS = ['curl/', 'wget/', 'postman', 'insomnia', 'httpie', 'python-requests'];

function identifyCrawler(userAgent) {
  if (!userAgent) return null;
  
  const ua = userAgent.toLowerCase();
  
  // Check ignore list first
  for (const pattern of IGNORE_PATTERNS) {
    if (ua.includes(pattern)) return null;
  }
  
  // Check known crawlers
  for (const [needle, identity] of Object.entries(CRAWLERS)) {
    if (ua.includes(needle)) {
      return identity;
    }
  }
  
  // Check for generic bot patterns
  const botPatterns = [
    'bot/', 'bot;', 'bot ', 'bot)',
    'crawler/', 'crawler;', 'crawler ',
    'spider/', 'spider;', 'spider ',
  ];
  
  for (const pattern of botPatterns) {
    if (ua.includes(pattern)) {
      return { label: 'UndeclaredBot', operator: 'Undeclared' };
    }
  }
  
  return null;
}

async function reportSighting(env, path, crawler) {
  if (!env.HARBOUR_URL || !env.HARBOUR_SITE_ID || !env.HARBOUR_INGEST_KEY) {
    console.warn('Harbour sensor not configured');
    return;
  }
  
  const url = `${env.HARBOUR_URL}/api/sites/${env.HARBOUR_SITE_ID}/sightings`;
  
  try {
    await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${env.HARBOUR_INGEST_KEY}`,
      },
      body: JSON.stringify({
        crawler: crawler.label,
        operator: crawler.operator,
        path: path,
      }),
    });
  } catch (error) {
    console.error('Failed to report sighting:', error);
  }
}

export default {
  async fetch(request, env, ctx) {
    const userAgent = request.headers.get('user-agent') || '';
    const url = new URL(request.url);
    const path = url.pathname;
    
    // Identify crawler
    const crawler = identifyCrawler(userAgent);
    
    // Report asynchronously if it's a crawler
    if (crawler) {
      ctx.waitUntil(reportSighting(env, path, crawler));
    }
    
    // Continue with normal request handling
    // Replace this with your actual origin fetch or return response
    return fetch(request);
  },
};
