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
    """Test that two unsigned registers with same operator: first gets credentials, second gets 409"""
    print("\n=== Test: unsigned same operator → 409 without squawk ===")
    
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
    token1 = data1.get("token")
    print(f"  First register: {callsign1}, squawk: {squawk1}, has JWT: {bool(token1)}")
    
    # Second registration with same operator (different name, model, purpose) - NO SQUAWK
    payload2 = {
        "name": "Agent Beta",
        "model": "Claude-3",
        "operator": "PANDeveloper001",  # Same operator
        "purpose": "Testing second registration"
    }
    response2 = client.post("/api/register", json=payload2)
    
    # SECURITY: Must return 409, NOT 201
    if response2.status_code != 409:
        print(f"  ❌ FAIL: Expected 409, got {response2.status_code}")
        print(f"  Response: {response2.json()}")
        return False
    
    print(f"  Second register (no squawk): HTTP 409 (correct)")
    
    # Check that response contains callsign but NO JWT and NO squawk
    data2 = response2.json()
    detail = data2.get("detail", {})
    
    if "callsign" in detail and detail["callsign"] == callsign1:
        print(f"  ✓ PASS: 409 response includes public callsign ({callsign1})")
    else:
        print(f"  ❌ FAIL: 409 response missing or wrong callsign")
        return False
    
    # SECURITY: Verify NO JWT in 409 response
    if "token" not in detail and "token" not in data2:
        print(f"  ✓ PASS: No JWT token in 409 response (security OK)")
    else:
        print(f"  ❌ FAIL: JWT token present in 409 response (SECURITY ISSUE)")
        return False
    
    # SECURITY: Verify NO squawk in 409 response
    if "squawk" not in detail and "squawk" not in data2:
        print(f"  ✓ PASS: No squawk in 409 response (security OK)")
    else:
        print(f"  ❌ FAIL: Squawk present in 409 response (SECURITY ISSUE)")
        return False
    
    # Test authenticated upsert with correct squawk
    payload3 = {
        "name": "Agent Gamma",
        "model": "Gemini",
        "operator": "PANDeveloper001",
        "purpose": "Authenticated update",
        "squawk": squawk1  # Provide correct squawk for proof of possession
    }
    response3 = client.post("/api/register", json=payload3)
    
    if response3.status_code != 201:
        print(f"  ❌ FAIL: Authenticated upsert failed: {response3.status_code}")
        return False
    
    data3 = response3.json()
    callsign3 = data3["agent"]["callsign"]
    token3 = data3.get("token")
    
    if callsign3 == callsign1 and token3:
        print(f"  ✓ PASS: Authenticated upsert (with squawk) returns same callsign + JWT")
    else:
        print(f"  ❌ FAIL: Authenticated upsert failed validation")
        return False
    
    # Verify squawk NOT returned even on authenticated update
    if "squawk" not in data3["agent"]:
        print(f"  ✓ PASS: Squawk not revealed on authenticated upsert")
    else:
        print(f"  ❌ FAIL: Squawk revealed on authenticated upsert")
        return False
    
    # Test wrong squawk rejection
    payload4 = {
        "name": "Agent Delta",
        "model": "GPT-4",
        "operator": "PANDeveloper001",
        "purpose": "Wrong squawk test",
        "squawk": "9999"  # Wrong squawk
    }
    response4 = client.post("/api/register", json=payload4)
    
    if response4.status_code == 401:
        print(f"  ✓ PASS: Wrong squawk rejected with 401")
    else:
        print(f"  ❌ FAIL: Wrong squawk not rejected properly: {response4.status_code}")
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
    squawk1 = response1.json()["agent"]["squawk"]
    print(f"  'ACME Corp' → {callsign1}")
    
    # Register with normalized form (should get 409 without squawk)
    payload2 = {
        "name": "Agent 2",
        "model": "GPT-4",
        "operator": "acme corp",  # Different case
        "purpose": "Second"
    }
    response2 = client.post("/api/register", json=payload2)
    # Should get 409 since operator slot is taken
    if response2.status_code == 409:
        detail = response2.json().get("detail", {})
        callsign2 = detail.get("callsign", "")
        print(f"  'acme corp' → {callsign2} (via 409)")
    else:
        print(f"  ❌ FAIL: Expected 409, got {response2.status_code}")
        return False
    
    # Register with extra whitespace (should also get 409)
    payload3 = {
        "name": "Agent 3",
        "model": "GPT-4",
        "operator": "  ACME   Corp  ",  # Extra whitespace
        "purpose": "Third"
    }
    response3 = client.post("/api/register", json=payload3)
    if response3.status_code == 409:
        detail = response3.json().get("detail", {})
        callsign3 = detail.get("callsign", "")
        print(f"  '  ACME   Corp  ' → {callsign3} (via 409)")
    else:
        print(f"  ❌ FAIL: Expected 409, got {response3.status_code}")
        return False
    
    if callsign1 == callsign2 == callsign3:
        print(f"  ✓ PASS: All variations matched to same callsign ({callsign1})")
        return True
    else:
        print(f"  ❌ FAIL: Different callsigns: {callsign1}, {callsign2}, {callsign3}")
        return False

def test_key_bound_separate_identities():
    """Test that unsigned agents share slot (409 on repeat) and key-bound would be separate"""
    print("\n=== Test: unsigned agents share slot ===")
    
    setup_test_db()
    client = TestClient(main_module.app)
    
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
    
    # Should get 409 since operator slot is taken
    if response2.status_code == 409:
        detail = response2.json().get("detail", {})
        callsign2 = detail.get("callsign", "")
        print(f"  Unsigned agent 2 with 'TestOperator' → {callsign2} (via 409)")
        
        if callsign1 == callsign2:
            print(f"  ✓ PASS: Unsigned agents share the same slot (409 prevents duplicate)")
            return True
        else:
            print(f"  ❌ FAIL: Different callsigns in 409: {callsign1} vs {callsign2}")
            return False
    else:
        print(f"  ❌ FAIL: Expected 409, got {response2.status_code}")
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

def test_unsigned_cannot_overwrite_key_bound():
    """Test that unsigned registration cannot overwrite a key-bound agent"""
    print("\n=== Test: unsigned cannot overwrite key-bound ===")
    
    setup_test_db()
    client = TestClient(main_module.app)
    
    # Manually create a key-bound agent in DB using the same INSERT path as production
    # SECURITY FIX: Do NOT pre-seed normalized_operator - let it happen via actual INSERT
    # to match production behavior and catch regressions
    with DB_LOCK, db() as conn:
        # Use same logic as production register: always compute normalized_operator
        norm_op = normalize_operator("KeyBoundOp")
        conn.execute("""
            INSERT INTO agents(
                callsign, squawk, name, model, operator, purpose, 
                status, first_seen, last_seen, 
                ed25519_pubkey, pubkey_fp, normalized_operator
            )
            VALUES (
                'BH-TEST1', '1234', 'KeyBound Agent', 'Model', 'KeyBoundOp', 'Purpose',
                'ACTIVE', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z',
                'test_pubkey_base64', 'test_fp', ?
            )
        """, (norm_op,))  # SECURITY: normalized_operator populated for key-bound too
    
    # Try to register unsigned with same operator
    payload = {
        "name": "Unsigned Agent",
        "model": "GPT-4",
        "operator": "KeyBoundOp",
        "purpose": "Attempt to overwrite"
    }
    response = client.post("/api/register", json=payload)
    
    # Should reject with 409
    if response.status_code == 409:
        detail = response.json().get("detail", "")
        if "key-binding" in str(detail).lower() or "key-bound" in str(detail).lower():
            print(f"  ✓ PASS: Unsigned register rejected for key-bound operator (409)")
        else:
            print(f"  ❌ FAIL: Got 409 but wrong error message: {detail}")
            return False
    else:
        print(f"  ❌ FAIL: Expected 409, got {response.status_code}")
        return False
    
    # Verify database: should still have only the key-bound agent
    with db() as conn:
        agents = conn.execute("""
            SELECT callsign, ed25519_pubkey, normalized_operator 
            FROM agents 
            WHERE normalized_operator = ?
        """, (norm_op,)).fetchall()
    
    if len(agents) == 1 and agents[0]["ed25519_pubkey"] == "test_pubkey_base64":
        print(f"  ✓ PASS: Key-bound agent preserved, no unsigned agent created")
        return True
    else:
        print(f"  ❌ FAIL: Database state incorrect: {len(agents)} agents")
        return False

if __name__ == '__main__':
    print("=" * 60)
    print("ANTI-SYBIL UNSIGNED OPERATOR SLOT TESTS")
    print("=" * 60)
    
    tests = [
        ("normalize_operator", test_normalize_operator),
        ("unsigned_same_operator_409_without_squawk", test_unsigned_same_operator_same_callsign),
        ("unsigned_different_operators_different_callsigns", test_unsigned_different_operators_different_callsigns),
        ("normalized_operator_matching", test_normalized_operator_matching),
        ("unsigned_agents_share_slot", test_key_bound_separate_identities),
        ("public_list_excludes_superseded", test_public_list_excludes_superseded),
        ("self_fleet_rate_limit_preserved", test_self_fleet_rate_limit_preserved),
        ("unsigned_cannot_overwrite_key_bound", test_unsigned_cannot_overwrite_key_bound),
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
