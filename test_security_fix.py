#!/usr/bin/env python3
"""Test script for squawk security fix"""
import os
import sys
import sqlite3
from pathlib import Path

# Set up database path before importing main
os.environ['DATABASE_PATH'] = '/tmp/harbour-data/test_agent_black_hole.db'

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.main import public_agent, db, init_db

def test_public_agent_excludes_squawk():
    """Test that public_agent() does not include squawk"""
    # Initialize database
    db_path = Path(os.environ['DATABASE_PATH'])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    init_db()
    
    # Create a test agent
    with db() as conn:
        conn.execute("""
            INSERT INTO agents(callsign, squawk, name, model, operator, purpose, first_seen, last_seen, ed25519_pubkey, pubkey_fp)
            VALUES ('BH-9999', '1234', 'TestAgent', 'TestModel', 'TestOp', 'Testing', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', NULL, NULL)
        """)
        row = conn.execute("SELECT * FROM agents WHERE callsign='BH-9999'").fetchone()
    
    # Test public_agent() serialization
    agent_data = public_agent(row)
    
    print("Testing public_agent() output:")
    print(f"  Keys: {sorted(agent_data.keys())}")
    
    # Check that squawk is NOT in the public agent data
    if 'squawk' in agent_data:
        print("  ❌ FAIL: squawk is present in public_agent() output")
        print(f"  Squawk value: {agent_data['squawk']}")
        return False
    else:
        print("  ✓ PASS: squawk is NOT present in public_agent() output")
    
    # Check that expected fields ARE present
    expected_fields = ['callsign', 'name', 'model', 'operator', 'purpose', 'status', 'first_seen', 'last_seen', 'key_bound']
    for field in expected_fields:
        if field not in agent_data:
            print(f"  ❌ FAIL: expected field '{field}' is missing")
            return False
    print(f"  ✓ PASS: all expected fields present")
    
    return True

def test_database_has_squawk():
    """Verify that squawk is still stored in database"""
    with db() as conn:
        row = conn.execute("SELECT squawk FROM agents WHERE callsign='BH-9999'").fetchone()
    
    print("\nTesting database storage:")
    if row and row['squawk'] == '1234':
        print(f"  ✓ PASS: squawk is stored in database (value: {row['squawk']})")
        return True
    else:
        print("  ❌ FAIL: squawk not found in database")
        return False

if __name__ == '__main__':
    try:
        test1 = test_public_agent_excludes_squawk()
        test2 = test_database_has_squawk()
        
        if test1 and test2:
            print("\n✅ All tests passed!")
            sys.exit(0)
        else:
            print("\n❌ Some tests failed")
            sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error running tests: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
