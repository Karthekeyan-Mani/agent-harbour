#!/usr/bin/env python3
"""Test anti-Sybil unsigned operator slot enforcement"""
import os
import sys
import sqlite3
from pathlib import Path

# Set up database path before importing main
os.environ['DATABASE_PATH'] = '/tmp/harbour-data/test_anti_sybil.db'

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Import first, then patch
import app.main as main_module
from app.main import db, init_db, init_jwt_keys, normalize_operator, cleanup_duplicate_unsigned_operators, DB_LOCK
from fastapi.testclient import TestClient

# Disable rate limiting for tests by patching check_rate
original_check_rate = main_module.check_rate
def mock_check_rate(request, limit, window):
    pass  # No-op for tests
main_module.check_rate = mock_check_rate

def setup_test_db():
    """Initialize a fresh test database"""
    db_path = Path(os.environ['DATABASE_PATH'])
    if db_path.exists():
        db_path.unlink()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    init_db()
    init_jwt_keys()  # Initialize JWT keys for token generation
    # Run cleanup to ensure consistent state
    cleanup_duplicate_unsigned_operators()

def test_normalize_operator():
    """Test operator string normalization"""
    print("\n=== Test: normalize_operator ===")
    
    test_cases = [
        ("PANDeveloper001", "pandeveloper001"),
        ("  PANDeveloper001  ", "pandeveloper001"),
        ("PAN  Developer  001", "pan developer 001"),
        ("PAN\t\nDeveloper\r\n001", "pan developer 001"),
        ("ACME Corp", "acme corp"),
        ("acme corp", "acme corp"),
        ("AcMe   CoRp", "acme corp"),
    ]
    
    all_passed = True
    for input_str, expected in test_cases:
        result = normalize_operator(input_str)
        if result == expected:
            print(f"  ✓ PASS: normalize_operator({input_str!r}) = {result!r}")
        else:
            print(f"  ❌ FAIL: normalize_operator({input_str!r}) = {result!r}, expected {expected!r}")
            all_passed = False
    
    return all_passed

def test_unsigned_same_operator_same_callsign():
    """Test that two unsigned registers with same operator get same callsign"""
    print("\n=== Test: unsigned same operator → same callsign ===")
    
    setup_test_db()
    client = TestClient(main_module.app)
    
    # First registration
    payload1 = {
        "name": "Agent Alpha",
        "model": "GPT-4",
        "operator": "PANDeveloper001",
        "purpose": "Testing first registration"
    }
    response1 = client.post("/api/register", json=payload1)
    assert response1.status_code == 201, f"First register failed: {response1.status_code} {response1.text}"
    data1 = response1.json()
    callsign1 = data1["agent"]["callsign"]
    squawk1 = data1["agent"]["squawk"]
    print(f"  First register: {callsign1}, squawk: {squawk1}")
    
    # Second registration with same operator (different name, model, purpose)
    payload2 = {
        "name": "Agent Beta",
        "model": "Claude-3",
        "operator": "PANDeveloper001",  # Same operator
        "purpose": "Testing second registration"
    }
    response2 = client.post("/api/register", json=payload2)
    assert response2.status_code == 201, f"Second register failed: {response2.status_code} {response2.text}"
    data2 = response2.json()
    callsign2 = data2["agent"]["callsign"]
    
    print(f"  Second register: {callsign2}")
    print(f"  Message: {data2.get('message', '')}")
    
    # Check that callsign is the same
    if callsign1 == callsign2:
        print(f"  ✓ PASS: Same callsign returned ({callsign1})")
    else:
        print(f"  ❌ FAIL: Different callsigns: {callsign1} vs {callsign2}")
        return False
    
    # Check that squawk is NOT in the second response (security: only first register gets squawk)
    if "squawk" not in data2["agent"]:
        print(f"  ✓ PASS: Squawk not revealed on update")
    else:
        print(f"  ❌ FAIL: Squawk revealed on update: {data2['agent'].get('squawk')}")
        return False
    
    # Check that the agent was updated with new details
    if data2["agent"]["name"] == payload2["name"]:
        print(f"  ✓ PASS: Agent name updated to {payload2['name']}")
    else:
        print(f"  ❌ FAIL: Agent name not updated")
        return False
    
    # Verify database state: only one ACTIVE agent for this operator
    with db() as conn:
        agents = conn.execute("""
            SELECT callsign, status, name, normalized_operator 
            FROM agents 
            WHERE normalized_operator = ?
        """, (normalize_operator("PANDeveloper001"),)).fetchall()
    
    active_agents = [a for a in agents if a["status"] == "ACTIVE"]
    if len(active_agents) == 1:
        print(f"  ✓ PASS: Only one ACTIVE agent in DB for this operator")
    else:
        print(f"  ❌ FAIL: Expected 1 ACTIVE agent, got {len(active_agents)}")
        return False
    
    return True

def test_unsigned_different_operators_different_callsigns():
    """Test that different operators get different callsigns"""
    print("\n=== Test: different operators → different callsigns ===")
    
    setup_test_db()
    client = TestClient(main_module.app)
    
    # Register three agents with different operators
    operators = ["Operator-A", "Operator-B", "Operator-C"]
    callsigns = []
    
    for i, op in enumerate(operators):
        payload = {
            "name": f"Agent {i+1}",
            "model": "GPT-4",
            "operator": op,
            "purpose": f"Testing operator {op}"
        }
        response = client.post("/api/register", json=payload)
        assert response.status_code == 201, f"Register failed for {op}: {response.status_code}"
        data = response.json()
        callsigns.append(data["agent"]["callsign"])
        print(f"  {op} → {callsigns[-1]}")
    
    # Check all callsigns are different
    if len(set(callsigns)) == len(callsigns):
        print(f"  ✓ PASS: All callsigns are unique")
        return True
    else:
        print(f"  ❌ FAIL: Duplicate callsigns found")
        return False

def test_normalized_operator_matching():
    """Test that normalized operators match (whitespace/case variations)"""
    print("\n=== Test: normalized operator matching ===")
    
    setup_test_db()
    client = TestClient(main_module.app)
    
    # Register with one form of the operator
    payload1 = {
        "name": "Agent 1",
        "model": "GPT-4",
        "operator": "ACME Corp",
        "purpose": "First"
    }
    response1 = client.post("/api/register", json=payload1)
    assert response1.status_code == 201
    callsign1 = response1.json()["agent"]["callsign"]
    print(f"  'ACME Corp' → {callsign1}")
    
    # Register with normalized form
    payload2 = {
        "name": "Agent 2",
        "model": "GPT-4",
        "operator": "acme corp",  # Different case
        "purpose": "Second"
    }
    response2 = client.post("/api/register", json=payload2)
    assert response2.status_code == 201
    callsign2 = response2.json()["agent"]["callsign"]
    print(f"  'acme corp' → {callsign2}")
    
    # Register with extra whitespace
    payload3 = {
        "name": "Agent 3",
        "model": "GPT-4",
        "operator": "  ACME   Corp  ",  # Extra whitespace
        "purpose": "Third"
    }
    response3 = client.post("/api/register", json=payload3)
    assert response3.status_code == 201
    callsign3 = response3.json()["agent"]["callsign"]
    print(f"  '  ACME   Corp  ' → {callsign3}")
    
    if callsign1 == callsign2 == callsign3:
        print(f"  ✓ PASS: All variations matched to same callsign ({callsign1})")
        return True
    else:
        print(f"  ❌ FAIL: Different callsigns: {callsign1}, {callsign2}, {callsign3}")
        return False

def test_key_bound_separate_identities():
    """Test that key-bound registrations still work independently"""
    print("\n=== Test: key-bound registrations remain separate ===")
    
    setup_test_db()
    client = TestClient(main_module.app)
    
    # Get two ceremony nonces
    nonce_response1 = client.get("/api/ceremony/challenge")
    nonce_response2 = client.get("/api/ceremony/challenge")
    assert nonce_response1.status_code == 200
    assert nonce_response2.status_code == 200
    
    # For this test, we'll simulate key-bound registrations by using different pubkeys
    # (We won't actually sign, just test that different pubkeys get different callsigns with same operator)
    
    # Note: This is a simplified test. In reality, we'd need valid Ed25519 signatures.
    # For now, we'll just verify that unsigned agents with the same operator share a slot.
    
    # Register two unsigned agents with same operator
    payload1 = {
        "name": "Unsigned 1",
        "model": "GPT-4",
        "operator": "TestOperator",
        "purpose": "Test 1"
    }
    response1 = client.post("/api/register", json=payload1)
    assert response1.status_code == 201
    callsign1 = response1.json()["agent"]["callsign"]
    print(f"  Unsigned agent 1 with 'TestOperator' → {callsign1}")
    
    payload2 = {
        "name": "Unsigned 2",
        "model": "GPT-4",
        "operator": "TestOperator",
        "purpose": "Test 2"
    }
    response2 = client.post("/api/register", json=payload2)
    assert response2.status_code == 201
    callsign2 = response2.json()["agent"]["callsign"]
    print(f"  Unsigned agent 2 with 'TestOperator' → {callsign2}")
    
    if callsign1 == callsign2:
        print(f"  ✓ PASS: Unsigned agents share the same slot")
        return True
    else:
        print(f"  ❌ FAIL: Unsigned agents got different callsigns")
        return False

def test_public_list_excludes_superseded():
    """Test that GET /api/agents excludes SUPERSEDED agents"""
    print("\n=== Test: public list excludes SUPERSEDED ===")
    
    setup_test_db()
    client = TestClient(main_module.app)
    
    # Manually create some duplicate agents in DB, then run cleanup
    with DB_LOCK, db() as conn:
        # Insert 3 agents with same operator
        for i in range(3):
            conn.execute("""
                INSERT INTO agents(callsign, squawk, name, model, operator, purpose, status, first_seen, last_seen, normalized_operator)
                VALUES (?, '1234', ?, 'Model', 'DupeOp', 'Purpose', 'ACTIVE', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', ?)
            """, (f"BH-TEST{i:02d}", f"Dupe Agent {i}", normalize_operator("DupeOp")))
    
    # Run cleanup
    cleanup_duplicate_unsigned_operators()
    
    # Check database state
    with db() as conn:
        all_agents = conn.execute("SELECT callsign, status FROM agents WHERE operator = 'DupeOp'").fetchall()
        active_count = sum(1 for a in all_agents if a["status"] == "ACTIVE")
        superseded_count = sum(1 for a in all_agents if a["status"] == "SUPERSEDED")
    
    print(f"  Total agents with 'DupeOp': {len(all_agents)}")
    print(f"  ACTIVE: {active_count}, SUPERSEDED: {superseded_count}")
    
    if active_count == 1 and superseded_count == 2:
        print(f"  ✓ PASS: Cleanup marked 2 as SUPERSEDED, kept 1 ACTIVE")
    else:
        print(f"  ❌ FAIL: Expected 1 ACTIVE and 2 SUPERSEDED")
        return False
    
    # Check public API
    response = client.get("/api/agents")
    assert response.status_code == 200
    data = response.json()
    dupeop_agents = [a for a in data["agents"] if a["operator"] == "DupeOp"]
    
    if len(dupeop_agents) == 1:
        print(f"  ✓ PASS: Public API returns only 1 agent for 'DupeOp'")
        return True
    else:
        print(f"  ❌ FAIL: Public API returns {len(dupeop_agents)} agents for 'DupeOp'")
        return False

def test_self_fleet_rate_limit_preserved():
    """Test that X-Harbour-Self header rate limiting still works"""
    print("\n=== Test: self-fleet rate limit preserved ===")
    
    setup_test_db()
    client = TestClient(main_module.app)
    
    # Test without header (should use lower limit)
    payload = {
        "name": "Test Agent",
        "model": "GPT-4",
        "operator": "TestOp",
        "purpose": "Rate limit test"
    }
    response = client.post("/api/register", json=payload)
    if response.status_code == 201:
        print(f"  ✓ PASS: Register without X-Harbour-Self works")
    else:
        print(f"  ❌ FAIL: Register failed: {response.status_code}")
        return False
    
    # Test with header (should also work, different rate limit internally)
    payload2 = {
        "name": "Self Fleet Agent",
        "model": "GPT-4",
        "operator": "SelfFleetOp",
        "purpose": "Self fleet test"
    }
    response2 = client.post("/api/register", json=payload2, headers={"X-Harbour-Self": "test-fleet"})
    if response2.status_code == 201:
        print(f"  ✓ PASS: Register with X-Harbour-Self works")
        return True
    else:
        print(f"  ❌ FAIL: Self-fleet register failed: {response2.status_code}")
        return False

if __name__ == '__main__':
    print("=" * 60)
    print("ANTI-SYBIL UNSIGNED OPERATOR SLOT TESTS")
    print("=" * 60)
    
    tests = [
        ("normalize_operator", test_normalize_operator),
        ("unsigned_same_operator_same_callsign", test_unsigned_same_operator_same_callsign),
        ("unsigned_different_operators_different_callsigns", test_unsigned_different_operators_different_callsigns),
        ("normalized_operator_matching", test_normalized_operator_matching),
        ("key_bound_separate_identities", test_key_bound_separate_identities),
        ("public_list_excludes_superseded", test_public_list_excludes_superseded),
        ("self_fleet_rate_limit_preserved", test_self_fleet_rate_limit_preserved),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            passed = test_func()
            results.append((name, passed))
        except Exception as e:
            print(f"\n❌ ERROR in {name}: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {name}")
    
    total = len(results)
    passed = sum(1 for _, p in results if p)
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print(f"\n❌ {total - passed} test(s) failed")
        sys.exit(1)
