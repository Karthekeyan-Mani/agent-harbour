#!/usr/bin/env python3
"""
Test rotation of weak 4-digit squawks to high-entropy ping_secret
"""
import os
import sys
from pathlib import Path

# Set up database path before importing
os.environ['DATABASE_PATH'] = '/tmp/harbour-data/test_rotation_agent_black_hole.db'

sys.path.insert(0, str(Path(__file__).parent))

from fastapi.testclient import TestClient
from app.main import app, init_db, db, DB_LOCK

# Initialize test database
db_path = Path(os.environ['DATABASE_PATH'])
db_path.parent.mkdir(parents=True, exist_ok=True)
if db_path.exists():
    db_path.unlink()  # Start fresh
init_db()

client = TestClient(app)

def test_rotation_on_ping_with_weak_secret():
    """Test that ping with correct 4-digit squawk rotates to high-entropy"""
    print("\n=== Test: Rotation on ping with weak secret ===")
    
    # Manually insert agent with weak 4-digit squawk (simulating pre-rotation data)
    with DB_LOCK, db() as conn:
        conn.execute("""
            INSERT INTO agents(callsign, squawk, name, model, operator, purpose, first_seen, last_seen, status)
            VALUES ('BH-9001', '1234', 'WeakAgent', 'TestModel', 'TestOp', 'Testing rotation', 
                    datetime('now'), datetime('now'), 'ACTIVE')
        """)
    
    print("  Setup: Inserted agent with weak squawk='1234'")
    
    # Ping with the correct weak secret
    response = client.post("/api/ping", json={
        "callsign": "BH-9001",
        "ping_secret": "1234"  # Correct weak secret
    })
    
    print(f"  Ping response status: {response.status_code}")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    print(f"  Response keys: {sorted(data.keys())}")
    
    # CRITICAL: Should return new ping_secret during rotation
    assert 'ping_secret' in data, "❌ FAIL: ping_secret not returned during rotation"
    new_secret = data['ping_secret']
    print(f"  ✓ PASS: New ping_secret returned (length: {len(new_secret)} chars)")
    
    # Verify new secret is high-entropy
    assert len(new_secret) >= 16, f"❌ FAIL: New secret too short ({len(new_secret)} chars)"
    assert not (len(new_secret) == 4 and new_secret.isdigit()), "❌ FAIL: New secret is still 4-digit"
    print(f"  ✓ PASS: New secret is high-entropy")
    
    # Verify message indicates rotation
    assert 'rotated' in data['message'].lower(), "❌ FAIL: Message doesn't indicate rotation"
    print(f"  ✓ PASS: Message indicates rotation: {data['message']}")
    
    # Verify JWT is minted
    assert 'token' in data, "❌ FAIL: No token in response"
    print(f"  ✓ PASS: JWT minted")
    
    # Verify database was updated
    with DB_LOCK, db() as conn:
        row = conn.execute("SELECT squawk FROM agents WHERE callsign='BH-9001'").fetchone()
        stored_secret = row['squawk']
        print(f"  DB check: Stored secret length: {len(stored_secret)} chars")
        assert stored_secret == new_secret, "❌ FAIL: DB not updated with new secret"
        print(f"  ✓ PASS: Database updated with new high-entropy secret")
    
    return "BH-9001", new_secret

def test_old_weak_secret_fails_after_rotation(callsign):
    """Test that old 4-digit squawk fails after rotation"""
    print("\n=== Test: Old weak secret fails after rotation ===")
    
    # Try to ping with old weak secret
    response = client.post("/api/ping", json={
        "callsign": callsign,
        "ping_secret": "1234"  # Old weak secret
    })
    
    print(f"  Ping with old secret status: {response.status_code}")
    assert response.status_code == 404, f"Expected 404, got {response.status_code}"
    print(f"  ✓ PASS: Old weak secret correctly rejected with 404")
    
    data = response.json()
    assert 'detail' in data, "No error detail in response"
    print(f"  Error message: {data['detail']}")
    print(f"  ✓ PASS: Old 4-digit secret never works again")

def test_new_secret_works_and_no_re_return(callsign, new_secret):
    """Test that new secret works and ping_secret is NOT returned again"""
    print("\n=== Test: New secret works, no re-return ===")
    
    # Ping with new high-entropy secret
    response = client.post("/api/ping", json={
        "callsign": callsign,
        "ping_secret": new_secret
    })
    
    print(f"  Ping with new secret status: {response.status_code}")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    print(f"  Response keys: {sorted(data.keys())}")
    
    # CRITICAL: Should NOT return ping_secret again (only during rotation or register)
    assert 'ping_secret' not in data, "❌ FAIL: ping_secret returned again (should be one-time)"
    print(f"  ✓ PASS: ping_secret NOT returned (one-time only)")
    
    # JWT should still be minted
    assert 'token' in data, "❌ FAIL: No token in response"
    print(f"  ✓ PASS: JWT minted successfully")
    
    # Message should be normal ping
    assert 'rotated' not in data['message'].lower(), "Message still mentions rotation"
    print(f"  ✓ PASS: Normal ping message: {data['message']}")

def test_legacy_squawk_field_accepted():
    """Test that legacy 'squawk' field name is accepted during transition"""
    print("\n=== Test: Legacy 'squawk' field accepted ===")
    
    # Register new agent to get high-entropy secret
    response = client.post("/api/register", json={
        "name": "LegacyTest",
        "model": "TestModel",
        "operator": "LegacyOp",
        "purpose": "Testing legacy field"
    })
    
    assert response.status_code == 201
    data = response.json()
    callsign = data['agent']['callsign']
    secret = data['agent']['ping_secret']
    print(f"  Registered {callsign} with high-entropy secret")
    
    # Ping using legacy 'squawk' field name
    response = client.post("/api/ping", json={
        "callsign": callsign,
        "squawk": secret  # Legacy field name
    })
    
    print(f"  Ping with legacy 'squawk' field status: {response.status_code}")
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    print(f"  ✓ PASS: Legacy 'squawk' field accepted")

def test_wrong_secret_gives_no_oracle():
    """Test that wrong secret on weak-squawk agent doesn't reveal if weak"""
    print("\n=== Test: Wrong secret gives no oracle (no 'weak' hint) ===")
    
    # Insert agent with weak squawk
    with DB_LOCK, db() as conn:
        conn.execute("""
            INSERT INTO agents(callsign, squawk, name, model, operator, purpose, first_seen, last_seen, status)
            VALUES ('BH-9002', '5678', 'OracleTest', 'TestModel', 'OracleOp', 'Testing oracle', 
                    datetime('now'), datetime('now'), 'ACTIVE')
        """)
    print("  Setup: Inserted agent with weak squawk='5678'")
    
    # Ping with wrong secret
    response = client.post("/api/ping", json={
        "callsign": "BH-9002",
        "ping_secret": "wrong_secret"
    })
    
    print(f"  Ping with wrong secret status: {response.status_code}")
    assert response.status_code == 404, f"Expected 404, got {response.status_code}"
    
    data = response.json()
    detail = data.get('detail', '').lower()
    
    # Should NOT mention "weak" or hint about the secret type
    assert 'weak' not in detail, "❌ FAIL: Error reveals secret is weak (oracle)"
    assert 'rotate' not in detail, "❌ FAIL: Error mentions rotation (oracle)"
    assert 'high-entropy' not in detail, "❌ FAIL: Error mentions entropy (oracle)"
    
    print(f"  Error message: {data['detail']}")
    print(f"  ✓ PASS: Generic error, no oracle that reveals weak vs wrong")

if __name__ == '__main__':
    try:
        # Test 1: Ping with correct weak secret rotates
        callsign, new_secret = test_rotation_on_ping_with_weak_secret()
        
        # Test 2: Old weak secret fails after rotation
        test_old_weak_secret_fails_after_rotation(callsign)
        
        # Test 3: New secret works, not returned again
        test_new_secret_works_and_no_re_return(callsign, new_secret)
        
        # Test 4: Legacy squawk field accepted
        test_legacy_squawk_field_accepted()
        
        # Test 5: No oracle for wrong secret
        test_wrong_secret_gives_no_oracle()
        
        print("\n" + "="*60)
        print("✅ ALL ROTATION TESTS PASSED!")
        print("="*60)
        print("\nRotation behavior verified:")
        print("  ✓ Ping with correct 4-digit rotates to high-entropy")
        print("  ✓ Returns new ping_secret once during rotation")
        print("  ✓ Old 4-digit never works again after rotation")
        print("  ✓ New secret works, ping_secret not returned again")
        print("  ✓ Legacy 'squawk' field name accepted")
        print("  ✓ Wrong secret gives generic error (no oracle)")
        
        sys.exit(0)
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error running tests: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
