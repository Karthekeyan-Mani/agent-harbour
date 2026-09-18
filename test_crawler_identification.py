#!/usr/bin/env python3
"""
Test script for hardened crawler identification.

Tests:
1. Word-boundary matching for short needles (especially "grok")
2. Self-fleet attribution via headers
3. Proper filtering of Cursor and Grok Bot traffic
4. Real crawler detection still working
"""

import sys
import re
from typing import Optional

# Inline the relevant functions for testing
SHORT_NEEDLES_REQUIRE_BOUNDARY = {"grok"}

CRAWLERS = {
    "gptbot": ("GPTBot", "OpenAI"),
    "bytespider": ("Bytespider", "ByteDance"),
    "claudebot": ("ClaudeBot", "Anthropic"),
    "grok": ("Grok", "xAI"),
    "deepseek": ("DeepSeek", "DeepSeek"),
}

IGNORE_USER_AGENTS = (
    "curl/", "wget/", "postman", "insomnia", "httpie", "python-requests",
    "grok bot",  # Cursor's Grok Bot (note: lowercase for matching)
    "cursor",    # Cursor IDE/agent traffic
)


def identify_crawler(user_agent: str, self_header: Optional[str] = None, fleet_header: Optional[str] = None) -> Optional[tuple[str, str]]:
    """Identify crawler from user agent and optional self-attribution headers."""
    # Priority 1: Self-fleet attribution via headers (Harbour's own agents)
    if self_header:
        # Sanitize the slug to prevent injection
        slug = re.sub(r'[^a-zA-Z0-9_-]', '', self_header[:50])
        if slug:
            return (f"Self-{slug}", "GrokBotFleet")
    
    if fleet_header and fleet_header.lower() in ("grokbot", "harbour"):
        return ("Self-internal", "GrokBotFleet")
    
    ua = user_agent.lower()
    
    # Priority 2: Ignore known development/testing tools and self-traffic
    if any(tool in ua for tool in IGNORE_USER_AGENTS):
        return None
    
    # Priority 3: Check known crawlers with word-boundary awareness
    for needle, identity in CRAWLERS.items():
        if needle in ua:
            # Short needles require word-boundary matching to avoid false positives
            if needle in SHORT_NEEDLES_REQUIRE_BOUNDARY:
                # Match "needle/" "needle;" "needle " "needle-" or at start/end of string
                word_boundary_patterns = (
                    f" {needle}/", f" {needle};", f" {needle} ", f" {needle}-",
                    f"/{needle}/", f"/{needle};", f"/{needle} ", f"/{needle}-",
                    f"-{needle}/", f"-{needle};", f"-{needle} ", f"-{needle}-",
                )
                # Also check if it's at the start or end with appropriate boundaries
                if (ua.startswith(f"{needle}/") or ua.startswith(f"{needle};") or 
                    ua.startswith(f"{needle} ") or ua.startswith(f"{needle}-") or
                    ua.endswith(f"/{needle}") or ua.endswith(f" {needle}") or
                    any(pattern in ua for pattern in word_boundary_patterns)):
                    return identity
                # If no word boundary match, skip this needle
                continue
            else:
                # Regular substring match for long needles
                return identity
    
    # Priority 4: Undeclared bot detection with precise patterns
    bot_patterns = (
        "bot/", "bot;", "bot ", "bot)", 
        "crawler/", "crawler;", "crawler ", 
        "spider/", "spider;", "spider ",
    )
    if any(pattern in ua for pattern in bot_patterns):
        return ("UndeclaredBot", "Undeclared")
    
    return None


def test_crawler_id():
    """Run test cases and report results."""
    tests = [
        # Self-fleet attribution tests
        {
            "name": "Self-fleet with X-Harbour-Self header",
            "ua": "Mozilla/5.0 (compatible; Python/3.11)",
            "self_header": "jarvis",
            "fleet_header": None,
            "expected": ("Self-jarvis", "GrokBotFleet"),
        },
        {
            "name": "Self-fleet with X-Harbour-Fleet header",
            "ua": "Mozilla/5.0 (compatible; Python/3.11)",
            "self_header": None,
            "fleet_header": "grokbot",
            "expected": ("Self-internal", "GrokBotFleet"),
        },
        # Ignore list tests (Cursor/Grok Bot false positive prevention)
        {
            "name": "Cursor IDE traffic (should be ignored)",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Cursor/0.42.0",
            "self_header": None,
            "fleet_header": None,
            "expected": None,
        },
        {
            "name": "Grok Bot (Cursor agent) traffic (should be ignored)",
            "ua": "Mozilla/5.0 (compatible; Grok Bot/1.0)",
            "self_header": None,
            "fleet_header": None,
            "expected": None,
        },
        {
            "name": "curl (should be ignored)",
            "ua": "curl/8.1.0",
            "self_header": None,
            "fleet_header": None,
            "expected": None,
        },
        # Word-boundary matching for "grok" (the main fix)
        {
            "name": "Real xAI Grok crawler with slash",
            "ua": "Mozilla/5.0 (compatible; xai-grok/1.0; +https://x.ai)",
            "self_header": None,
            "fleet_header": None,
            "expected": ("Grok", "xAI"),
        },
        {
            "name": "Real xAI Grok crawler at start",
            "ua": "grok/1.0 (+https://x.ai)",
            "self_header": None,
            "fleet_header": None,
            "expected": ("Grok", "xAI"),
        },
        {
            "name": "String containing 'grok' without word boundary (should catch as undeclared)",
            "ua": "Mozilla/5.0 (compatible; GrokkerBot/1.0)",
            "self_header": None,
            "fleet_header": None,
            "expected": ("UndeclaredBot", "Undeclared"),  # Not matched by "grok" needle, but caught as bot/
        },
        # Real crawler detection (should still work)
        {
            "name": "GPTBot (OpenAI)",
            "ua": "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)",
            "self_header": None,
            "fleet_header": None,
            "expected": ("GPTBot", "OpenAI"),
        },
        {
            "name": "ClaudeBot (Anthropic)",
            "ua": "Mozilla/5.0 (compatible; ClaudeBot/1.0; +https://www.anthropic.com)",
            "self_header": None,
            "fleet_header": None,
            "expected": ("ClaudeBot", "Anthropic"),
        },
        {
            "name": "Bytespider (ByteDance)",
            "ua": "Mozilla/5.0 (compatible; Bytespider; https://bytedance.com)",
            "self_header": None,
            "fleet_header": None,
            "expected": ("Bytespider", "ByteDance"),
        },
        # Undeclared bot detection
        {
            "name": "Undeclared bot with bot/",
            "ua": "MyCustomBot/1.0",
            "self_header": None,
            "fleet_header": None,
            "expected": ("UndeclaredBot", "Undeclared"),
        },
        {
            "name": "Regular browser (should be None)",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "self_header": None,
            "fleet_header": None,
            "expected": None,
        },
    ]
    
    passed = 0
    failed = 0
    
    print("=" * 80)
    print("Crawler Identification Test Suite")
    print("=" * 80)
    print()
    
    for test in tests:
        result = identify_crawler(
            test["ua"],
            self_header=test.get("self_header"),
            fleet_header=test.get("fleet_header")
        )
        
        status = "✓ PASS" if result == test["expected"] else "✗ FAIL"
        if result == test["expected"]:
            passed += 1
        else:
            failed += 1
        
        print(f"{status} | {test['name']}")
        if result != test["expected"]:
            print(f"     Expected: {test['expected']}")
            print(f"     Got:      {result}")
            print(f"     UA:       {test['ua'][:80]}")
        print()
    
    print("=" * 80)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 80)
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(test_crawler_id())
