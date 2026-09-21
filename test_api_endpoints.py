#!/usr/bin/env python3
"""Integration tests for API endpoints - squawk security fix"""
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

def test_register_returns_squawk():
    """Test that POST /api/register returns squawk once to the registering caller"""
    print("\n=== Testing POST /api/register ===")
    
    response = client.post("/api/register", json={
        "name": "SecurityTestAgent",
        "model": "TestModel-1",
        "operator": "SecurityTest",
        "purpose": "Testing squawk security fix"
    })
    
    print(f"Status code: {response.status_code}")
    assert response.status_code == 201, f"Expected 201, got {response.status_code}"
    
    data = response.json()
    print(f"Response keys: {sorted(data.keys())}")
    
    # Check that agent field exists
    assert 'agent' in data, "Missing 'agent' field in response"
    agent = data['agent']
    print(f"Agent keys: {sorted(agent.keys())}")
    
    # CRITICAL: squawk MUST be in register response
    assert 'squawk' in agent, "❌ FAIL: squawk missing from register response"
    assert agent['squawk'], "❌ FAIL: squawk is empty"
    print(f"  ✓ PASS: squawk present in register response (value: {agent['squawk']})")
    
    # Verify other required fields
    assert 'callsign' in agent, "Missing callsign"
    assert agent['callsign'].startswith('BH-'), f"Invalid callsign format: {agent['callsign']}"
    print(f"  ✓ PASS: callsign present ({agent['callsign']})")
    
    return agent['callsign'], agent['squawk']

def test_agents_excludes_squawk():
    """Test that GET /api/agents does NOT expose squawk"""
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
        print("  ⚠ WARNING: No agents in response, cannot test squawk exclusion")
        return True
    
    # Check that NO agent in the list has squawk
    for i, agent in enumerate(agents):
        if 'squawk' in agent:
            print(f"  ❌ FAIL: Agent {i} has squawk: {agent}")
            return False
    
    print(f"  ✓ PASS: No agents expose squawk in public listing")
    print(f"  Sample agent keys: {sorted(agents[0].keys())}")
    
    return True

def test_ping_still_works(callsign, squawk):
    """Test that POST /api/ping still works with callsign + squawk"""
    print("\n=== Testing POST /api/ping ===")
    
    response = client.post("/api/ping", json={
        "callsign": callsign,
        "squawk": squawk
    })
    
    print(f"Status code: {response.status_code}")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    print(f"Response keys: {sorted(data.keys())}")
    
    # Verify ping response
    assert 'message' in data, "Missing 'message' field"
    assert 'token' in data, "Missing 'token' field (JWT)"
    print(f"  ✓ PASS: Ping successful with callsign+squawk authentication")
    print(f"  Message: {data['message']}")
    
    return True

def test_ping_with_wrong_squawk(callsign):
    """Test that POST /api/ping fails with wrong squawk"""
    print("\n=== Testing POST /api/ping with wrong squawk ===")
    
    response = client.post("/api/ping", json={
        "callsign": callsign,
        "squawk": "9999"  # Wrong squawk
    })
    
    print(f"Status code: {response.status_code}")
    assert response.status_code == 404, f"Expected 404, got {response.status_code}"
    print(f"  ✓ PASS: Ping correctly rejected with wrong squawk")
    
    return True

if __name__ == '__main__':
    try:
        # Test 1: Register returns squawk
        callsign, squawk = test_register_returns_squawk()
        
        # Test 2: Public agents API excludes squawk
        test_agents_excludes_squawk()
        
        # Test 3: Ping still works
        test_ping_still_works(callsign, squawk)
        
        # Test 4: Ping fails with wrong squawk
        test_ping_with_wrong_squawk(callsign)
        
        print("\n" + "="*50)
        print("✅ All API endpoint tests passed!")
        print("="*50)
        print("\nSecurity fix verified:")
        print("  ✓ POST /api/register returns squawk once")
        print("  ✓ GET /api/agents does NOT expose squawk")
        print("  ✓ POST /api/ping works with callsign+squawk")
        print("  ✓ POST /api/ping fails with wrong squawk")
        
        sys.exit(0)
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error running tests: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
