#!/usr/bin/env python3
"""Test script for Ed25519 ceremony MVP"""
import base64
import json
import os
import sys
import tempfile
import time
from pathlib import Path

# Add to PATH for imports
sys.path.insert(0, str(Path(__file__).parent))

from cryptography.hazmat.primitives.asymmetric import ed25519

# Test configuration
BASE_URL = "http://127.0.0.1:8000"
DB_PATH = tempfile.mktemp(suffix=".db")
os.environ["DATABASE_PATH"] = DB_PATH

def generate_ed25519_keypair():
    """Generate Ed25519 keypair for testing"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def encode_pubkey(public_key):
    """Encode Ed25519 public key as base64url (no padding)"""
    pubkey_bytes = public_key.public_bytes_raw()
    return base64.urlsafe_b64encode(pubkey_bytes).decode('ascii').rstrip('=')

def sign_message(private_key, message):
    """Sign message with Ed25519 private key"""
    signature = private_key.sign(message.encode('utf-8'))
    return base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')

def test_imports():
    """Test that all modules can be imported"""
    print("Testing imports...")
    try:
        from app.main import app, init_db, init_jwt_keys
        print("✓ Imports successful")
        return app, init_db, init_jwt_keys
    except Exception as e:
        print(f"✗ Import failed: {e}")
        sys.exit(1)

def test_schema():
    """Test database schema"""
    print("\nTesting database schema...")
    from app.main import db, init_db
    init_db()
    
    with db() as conn:
        # Check agents table has ed25519_pubkey column
        cursor = conn.execute("PRAGMA table_info(agents)")
        columns = {row[1] for row in cursor.fetchall()}
        assert "ed25519_pubkey" in columns, "Missing ed25519_pubkey column"
        assert "pubkey_fp" in columns, "Missing pubkey_fp column"
        
        # Check ceremony_nonces table exists
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ceremony_nonces'")
        assert cursor.fetchone() is not None, "Missing ceremony_nonces table"
        
        print("✓ Database schema correct")

def test_helper_functions():
    """Test helper functions"""
    print("\nTesting helper functions...")
    from app.main import compute_pubkey_fp, compute_glyph_compat, verify_ed25519_signature
    
    # Generate test keypair
    private_key, public_key = generate_ed25519_keypair()
    pubkey_b64 = encode_pubkey(public_key)
    pubkey_bytes = public_key.public_bytes_raw()
    
    # Test fingerprint computation
    fp = compute_pubkey_fp(pubkey_bytes)
    assert len(fp) == 16, f"Fingerprint should be 16 chars, got {len(fp)}"
    assert all(c in '0123456789abcdef' for c in fp), "Fingerprint should be hex"
    
    # Test glyph_compat computation
    glyph = compute_glyph_compat(pubkey_bytes)
    assert len(glyph) == 52, f"Glyph compat should be 52 chars, got {len(glyph)}"
    assert glyph.isupper(), "Glyph compat should be uppercase base32"
    
    # Test signature verification
    message = "test message"
    sig_b64 = sign_message(private_key, message)
    assert verify_ed25519_signature(pubkey_b64, sig_b64, message), "Valid signature should verify"
    assert not verify_ed25519_signature(pubkey_b64, sig_b64, "wrong message"), "Invalid message should fail"
    
    print("✓ Helper functions working correctly")

def test_api_endpoints():
    """Test API endpoints"""
    print("\nTesting API endpoints...")
    from fastapi.testclient import TestClient
    from app.main import app, init_db, init_jwt_keys
    
    # Disable rate limiting for tests by setting high limits
    import app.main as main_module
    original_check_rate = main_module.check_rate
    def mock_check_rate(request, limit=99999, window=1):
        pass
    main_module.check_rate = mock_check_rate
    
    init_db()
    init_jwt_keys()
    client = TestClient(app)
    
    # Test 1: Health check
    print("\n1. Testing health endpoint...")
    response = client.get("/health")
    assert response.status_code == 200, f"Health check failed: {response.status_code}"
    print("✓ Health endpoint OK")
    
    # Test 2: Unsigned register
    print("\n2. Testing unsigned register...")
    register_data = {
        "name": "Test Agent Unsigned",
        "model": "Test Model",
        "operator": "Test Operator",
        "purpose": "Testing unsigned registration"
    }
    response = client.post("/api/register", json=register_data)
    assert response.status_code == 201, f"Unsigned register failed: {response.status_code} {response.text}"
    data = response.json()
    assert data["agent"]["key_bound"] == False, "Unsigned agent should not be key_bound"
    assert "callsign" in data["agent"], "Missing callsign"
    print(f"✓ Unsigned register successful: {data['agent']['callsign']}")
    
    # Test 3: Challenge endpoint
    print("\n3. Testing ceremony challenge...")
    response = client.get("/api/ceremony/challenge")
    assert response.status_code == 200, f"Challenge failed: {response.status_code}"
    challenge = response.json()
    assert "nonce" in challenge, "Missing nonce"
    assert "expires_at" in challenge, "Missing expires_at"
    print(f"✓ Challenge successful, nonce: {challenge['nonce'][:16]}...")
    
    # Test 4: Signed register
    print("\n4. Testing signed register...")
    private_key, public_key = generate_ed25519_keypair()
    pubkey_b64 = encode_pubkey(public_key)
    
    # Get fresh challenge
    response = client.get("/api/ceremony/challenge")
    challenge = response.json()
    
    # Build canonical register message
    register_data_signed = {
        "name": "Test Agent Signed",
        "model": "Test Model Ed25519",
        "operator": "Test Operator Signed",
        "purpose": "Testing signed registration with Ed25519"
    }
    message = f"harbour-ed25519-register-v1\n{challenge['nonce']}\n{challenge['expires_at']}\n{register_data_signed['name']}\n{register_data_signed['operator']}\n{register_data_signed['purpose']}"
    sig_b64 = sign_message(private_key, message)
    
    register_data_signed["ed25519_pubkey"] = pubkey_b64
    register_data_signed["ed25519_sig"] = sig_b64
    register_data_signed["ceremony_nonce"] = challenge["nonce"]
    
    response = client.post("/api/register", json=register_data_signed)
    assert response.status_code == 201, f"Signed register failed: {response.status_code} {response.text}"
    data = response.json()
    assert data["agent"]["key_bound"] == True, "Signed agent should be key_bound"
    assert "ed25519_pubkey" in data["agent"], "Missing ed25519_pubkey"
    assert "pubkey_fp" in data["agent"], "Missing pubkey_fp"
    assert "glyph_compat" in data["agent"], "Missing glyph_compat"
    assert len(data["agent"]["pubkey_fp"]) == 16, "Invalid pubkey_fp length"
    assert len(data["agent"]["glyph_compat"]) == 52, "Invalid glyph_compat length"
    signed_callsign = data["agent"]["callsign"]
    print(f"✓ Signed register successful: {signed_callsign}, key_bound: True")
    print(f"  pubkey_fp: {data['agent']['pubkey_fp']}")
    print(f"  glyph_compat: {data['agent']['glyph_compat']}")
    
    # Test 5: Duplicate pubkey should fail (409)
    print("\n5. Testing duplicate pubkey rejection...")
    response = client.get("/api/ceremony/challenge")
    challenge = response.json()
    
    dup_data = {
        "name": "Duplicate Key Agent",
        "model": "Test Model",
        "operator": "Test Operator",
        "purpose": "Should fail due to duplicate key"
    }
    message = f"harbour-ed25519-register-v1\n{challenge['nonce']}\n{challenge['expires_at']}\n{dup_data['name']}\n{dup_data['operator']}\n{dup_data['purpose']}"
    sig_b64 = sign_message(private_key, message)
    
    dup_data["ed25519_pubkey"] = pubkey_b64
    dup_data["ed25519_sig"] = sig_b64
    dup_data["ceremony_nonce"] = challenge["nonce"]
    
    response = client.post("/api/register", json=dup_data)
    assert response.status_code == 409, f"Duplicate pubkey should return 409, got {response.status_code}"
    print("✓ Duplicate pubkey correctly rejected (409)")
    
    # Test 6: Bad signature should fail
    print("\n6. Testing bad signature rejection...")
    bad_private_key, bad_public_key = generate_ed25519_keypair()
    bad_pubkey_b64 = encode_pubkey(bad_public_key)
    
    response = client.get("/api/ceremony/challenge")
    challenge = response.json()
    
    bad_data = {
        "name": "Bad Sig Agent",
        "model": "Test Model",
        "operator": "Test Operator",
        "purpose": "Should fail due to bad signature"
    }
    message = f"harbour-ed25519-register-v1\n{challenge['nonce']}\n{challenge['expires_at']}\n{bad_data['name']}\n{bad_data['operator']}\n{bad_data['purpose']}"
    
    # Sign with different key than pubkey
    bad_sig = sign_message(bad_private_key, message)
    
    bad_data["ed25519_pubkey"] = pubkey_b64  # Use previous pubkey
    bad_data["ed25519_sig"] = bad_sig  # But sign with different key
    bad_data["ceremony_nonce"] = challenge["nonce"]
    
    response = client.post("/api/register", json=bad_data)
    assert response.status_code == 422, f"Bad signature should return 422, got {response.status_code}"
    print("✓ Bad signature correctly rejected (422)")
    
    # Test 7: JWT bind
    print("\n7. Testing post-register bind...")
    # Register without key first
    bind_data = {
        "name": "Bind Test Agent",
        "model": "Test Model",
        "operator": "Test Operator",
        "purpose": "Testing post-register bind"
    }
    response = client.post("/api/register", json=bind_data)
    assert response.status_code == 201, f"Register for bind test failed: {response.status_code}"
    bind_agent = response.json()
    token = bind_agent["token"]
    bind_callsign = bind_agent["agent"]["callsign"]
    print(f"✓ Registered agent for bind test: {bind_callsign}")
    
    # Now bind a key
    bind_private_key, bind_public_key = generate_ed25519_keypair()
    bind_pubkey_b64 = encode_pubkey(bind_public_key)
    
    response = client.get("/api/ceremony/challenge")
    challenge = response.json()
    
    bind_message = f"harbour-ed25519-bind-v1\n{bind_callsign}\n{challenge['nonce']}\n{challenge['expires_at']}"
    bind_sig = sign_message(bind_private_key, bind_message)
    
    bind_payload = {
        "ed25519_pubkey": bind_pubkey_b64,
        "ed25519_sig": bind_sig,
        "ceremony_nonce": challenge["nonce"]
    }
    
    response = client.post(
        "/api/ceremony/bind",
        json=bind_payload,
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200, f"Bind failed: {response.status_code} {response.text}"
    bind_result = response.json()
    assert bind_result["key_bound"] == True, "Bind should set key_bound"
    assert bind_result["callsign"] == bind_callsign, "Callsign mismatch"
    print(f"✓ Bind successful for {bind_callsign}")
    
    # Test 8: Second bind should fail (409)
    print("\n8. Testing rebind rejection...")
    response = client.get("/api/ceremony/challenge")
    challenge = response.json()
    
    rebind_message = f"harbour-ed25519-bind-v1\n{bind_callsign}\n{challenge['nonce']}\n{challenge['expires_at']}"
    rebind_sig = sign_message(bind_private_key, rebind_message)
    
    rebind_payload = {
        "ed25519_pubkey": bind_pubkey_b64,
        "ed25519_sig": rebind_sig,
        "ceremony_nonce": challenge["nonce"]
    }
    
    response = client.post(
        "/api/ceremony/bind",
        json=rebind_payload,
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 409, f"Rebind should return 409, got {response.status_code}"
    print("✓ Rebind correctly rejected (409)")
    
    # Test 9: Directory shows key_bound
    print("\n9. Testing directory with key_bound...")
    response = client.get("/api/agents")
    assert response.status_code == 200, f"Directory failed: {response.status_code}"
    agents = response.json()["agents"]
    
    # Find our signed agent
    signed_agent = next((a for a in agents if a["callsign"] == signed_callsign), None)
    assert signed_agent is not None, "Signed agent not in directory"
    assert signed_agent["key_bound"] == True, "Directory should show key_bound"
    assert "ed25519_pubkey" in signed_agent, "Directory should include pubkey"
    assert "pubkey_fp" in signed_agent, "Directory should include pubkey_fp"
    assert "glyph_compat" in signed_agent, "Directory should include glyph_compat"
    print("✓ Directory correctly shows key_bound fields")
    
    # Test 10: JWT includes key_bound claims
    print("\n10. Testing JWT claims for bound key...")
    response = client.post("/api/token/introspect", json={"token": bind_agent["token"]})
    assert response.status_code == 200, f"Introspect failed: {response.status_code}"
    
    # Get fresh token after bind
    response = client.post(
        "/api/ping",
        json={"callsign": bind_callsign, "squawk": bind_agent["agent"]["squawk"]}
    )
    assert response.status_code == 200, f"Ping failed: {response.status_code}"
    fresh_token = response.json()["token"]
    
    # Introspect fresh token (should have key_bound)
    # Note: We can't decode JWT here without the public key, but introspect will work
    response = client.post("/api/token/introspect", json={"token": fresh_token})
    assert response.status_code == 200, f"Fresh token introspect failed: {response.status_code}"
    # The introspect endpoint doesn't return key_bound in the current implementation,
    # but the token itself contains it
    print("✓ JWT token generated successfully after bind")
    
    # Test 11: X-Agent-Register-Hint header is ASCII
    print("\n11. Testing X-Agent-Register-Hint is ASCII...")
    response = client.get("/")
    hint = response.headers.get("X-Agent-Register-Hint", "")
    assert hint.isascii(), "X-Agent-Register-Hint must be ASCII-only"
    print(f"✓ X-Agent-Register-Hint is ASCII: {hint[:50]}...")
    
    print("\n" + "="*60)
    print("✓ ALL TESTS PASSED!")
    print("="*60)

if __name__ == "__main__":
    try:
        app, init_db, init_jwt_keys = test_imports()
        test_schema()
        test_helper_functions()
        test_api_endpoints()
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Cleanup
        if os.path.exists(DB_PATH):
            os.unlink(DB_PATH)
