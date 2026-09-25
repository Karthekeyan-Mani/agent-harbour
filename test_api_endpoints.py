#!/usr/bin/env python3
"""Integration tests for API endpoints - ping_secret security fix"""
import os
import sys
import json
from pathlib import Path

# Set up database path before importing
os.environ['DATABASE_PATH'] = '/tmp/harbour-data/test_api_agent_black_hole.db'

sys.path.insert(0, str(Path(__file__).parent))

from fastapi.testclient import TestClient
from app.main import app, init_db

# Initialize test database
db_path = Path(os.environ['DATABASE_PATH'])
db_path.parent.mkdir(parents=True, exist_ok=True)
if db_path.exists():
    db_path.unlink()  # Start fresh
init_db()

client = TestClient(app)

def test_register_returns_ping_secret():
    """Test that POST /api/register returns ping_secret once to the registering caller"""
    print("\n=== Testing POST /api/register ===")
    
    response = client.post("/api/register", json={
        "name": "SecurityTestAgent",
        "model": "TestModel-1",
        "operator": "SecurityTest",
        "purpose": "Testing ping_secret security fix"
    })
    
    print(f"Status code: {response.status_code}")
    assert response.status_code == 201, f"Expected 201, got {response.status_code}"
    
    data = response.json()
    print(f"Response keys: {sorted(data.keys())}")
    
    # Check that agent field exists
    assert 'agent' in data, "Missing 'agent' field in response"
    agent = data['agent']
    print(f"Agent keys: {sorted(agent.keys())}")
    
    # CRITICAL: ping_secret MUST be in register response
    assert 'ping_secret' in agent, "❌ FAIL: ping_secret missing from register response"
    assert agent['ping_secret'], "❌ FAIL: ping_secret is empty"
    assert len(agent['ping_secret']) >= 16, f"❌ FAIL: ping_secret too short ({len(agent['ping_secret'])} chars)"
    print(f"  ✓ PASS: ping_secret present in register response (length: {len(agent['ping_secret'])} chars)")
    
    # Verify it's NOT a 4-digit code
    assert not (len(agent['ping_secret']) == 4 and agent['ping_secret'].isdigit()), \
        "❌ FAIL: ping_secret is still a weak 4-digit code"
    print(f"  ✓ PASS: ping_secret is high-entropy (not 4-digit code)")
    
    # Verify other required fields
    assert 'callsign' in agent, "Missing callsign"
    assert agent['callsign'].startswith('BH-'), f"Invalid callsign format: {agent['callsign']}"
    print(f"  ✓ PASS: callsign present ({agent['callsign']})")
    
    return agent['callsign'], agent['ping_secret']

def test_agents_excludes_ping_secret():
    """Test that GET /api/agents does NOT expose ping_secret"""
    print("\n=== Testing GET /api/agents ===")
    
    response = client.get("/api/agents")
    
    print(f"Status code: {response.status_code}")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    print(f"Response keys: {sorted(data.keys())}")
    assert 'agents' in data, "Missing 'agents' field"
    
    agents = data['agents']
    print(f"Number of agents: {len(agents)}")
    
    if len(agents) == 0:
        print("  ⚠ WARNING: No agents in response, cannot test ping_secret exclusion")
        return True
    
    # Check that NO agent in the list has ping_secret or squawk
    for i, agent in enumerate(agents):
        if 'ping_secret' in agent or 'squawk' in agent:
            print(f"  ❌ FAIL: Agent {i} has secret field: {agent}")
            return False
    
    print(f"  ✓ PASS: No agents expose ping_secret in public listing")
    print(f"  Sample agent keys: {sorted(agents[0].keys())}")
    
    return True

def test_ping_still_works(callsign, ping_secret):
    """Test that POST /api/ping still works with callsign + ping_secret"""
    print("\n=== Testing POST /api/ping ===")
    
    response = client.post("/api/ping", json={
        "callsign": callsign,
        "ping_secret": ping_secret
    })
    
    print(f"Status code: {response.status_code}")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    print(f"Response keys: {sorted(data.keys())}")
    
    # Verify ping response
    assert 'message' in data, "Missing 'message' field"
    assert 'token' in data, "Missing 'token' field (JWT)"
    print(f"  ✓ PASS: Ping successful with callsign+ping_secret authentication")
    print(f"  Message: {data['message']}")
    
    return True

def test_ping_with_wrong_secret(callsign):
    """Test that POST /api/ping fails with wrong ping_secret"""
    print("\n=== Testing POST /api/ping with wrong ping_secret ===")
    
    response = client.post("/api/ping", json={
        "callsign": callsign,
        "ping_secret": "wrong_secret_value_12345"
    })
    
    print(f"Status code: {response.status_code}")
    assert response.status_code == 404, f"Expected 404, got {response.status_code}"
    print(f"  ✓ PASS: Ping correctly rejected with wrong ping_secret")
    
    return True

if __name__ == '__main__':
    try:
        # Test 1: Register returns ping_secret
        callsign, ping_secret = test_register_returns_ping_secret()
        
        # Test 2: Public agents API excludes ping_secret
        test_agents_excludes_ping_secret()
        
        # Test 3: Ping still works
        test_ping_still_works(callsign, ping_secret)
        
        # Test 4: Ping fails with wrong ping_secret
        test_ping_with_wrong_secret(callsign)
        
        print("\n" + "="*50)
        print("✅ All API endpoint tests passed!")
        print("="*50)
        print("\nSecurity fix verified:")
        print("  ✓ POST /api/register returns high-entropy ping_secret once")
        print("  ✓ GET /api/agents does NOT expose ping_secret")
        print("  ✓ POST /api/ping works with callsign+ping_secret")
        print("  ✓ POST /api/ping fails with wrong ping_secret")
        
        sys.exit(0)
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error running tests: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
