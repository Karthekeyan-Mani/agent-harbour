#!/usr/bin/env python3
"""Tests for maintenance mode functionality"""
import os
import sys
from pathlib import Path

# Set up database path before importing
os.environ['DATABASE_PATH'] = '/tmp/harbour-data/test_maintenance_agent_black_hole.db'

sys.path.insert(0, str(Path(__file__).parent))

from fastapi.testclient import TestClient
from app.main import app, init_db

# Initialize test database
db_path = Path(os.environ['DATABASE_PATH'])
db_path.parent.mkdir(parents=True, exist_ok=True)
if db_path.exists():
    db_path.unlink()
init_db()


def test_normal_mode_allows_traffic():
    """Test that without MAINTENANCE_MODE, all routes work normally"""
    print("\n=== Testing normal mode (maintenance OFF) ===")
    
    # Ensure maintenance mode is off
    os.environ.pop('MAINTENANCE_MODE', None)
    
    # Need to reimport to pick up env change
    import importlib
    import app.main
    importlib.reload(app.main)
    from app.main import app as reloaded_app
    
    client = TestClient(reloaded_app)
    
    # Test home page
    response = client.get("/")
    print(f"GET / status: {response.status_code}")
    assert response.status_code == 200, "Home page should work in normal mode"
    
    # Test API endpoint
    response = client.get("/api/agents")
    print(f"GET /api/agents status: {response.status_code}")
    assert response.status_code == 200, "API should work in normal mode"
    
    # Test health endpoint
    response = client.get("/health")
    print(f"GET /health status: {response.status_code}")
    assert response.status_code == 200, "Health should work in normal mode"
    
    print("✓ Normal mode allows all traffic")


def test_maintenance_mode_blocks_html_routes():
    """Test that maintenance mode returns HTML 503 for browser requests"""
    print("\n=== Testing maintenance mode HTML routes ===")
    
    # Enable maintenance mode
    os.environ['MAINTENANCE_MODE'] = '1'
    
    # Reimport to pick up env change
    import importlib
    import app.main
    importlib.reload(app.main)
    from app.main import app as reloaded_app
    
    client = TestClient(reloaded_app)
    
    # Test home page with HTML accept header
    response = client.get("/", headers={"Accept": "text/html"})
    print(f"GET / status: {response.status_code}")
    assert response.status_code == 503, "Home page should return 503 in maintenance mode"
    assert "text/html" in response.headers.get("content-type", ""), "Should return HTML"
    assert "Harbour Closed" in response.text or "maintenance" in response.text.lower(), "Should show maintenance message"
    assert "Retry-After" in response.headers, "Should include Retry-After header"
    print(f"Retry-After: {response.headers['Retry-After']}")
    
    # Test leaderboard
    response = client.get("/leaderboard", headers={"Accept": "text/html"})
    print(f"GET /leaderboard status: {response.status_code}")
    assert response.status_code == 503, "Leaderboard should return 503 in maintenance mode"
    
    print("✓ Maintenance mode blocks HTML routes with proper 503 page")


def test_maintenance_mode_blocks_api_routes():
    """Test that maintenance mode returns JSON 503 for API requests"""
    print("\n=== Testing maintenance mode API routes ===")
    
    # Enable maintenance mode
    os.environ['MAINTENANCE_MODE'] = 'true'
    
    # Reimport
    import importlib
    import app.main
    importlib.reload(app.main)
    from app.main import app as reloaded_app
    
    client = TestClient(reloaded_app)
    
    # Test /api/agents
    response = client.get("/api/agents")
    print(f"GET /api/agents status: {response.status_code}")
    assert response.status_code == 503, "API should return 503 in maintenance mode"
    assert response.headers.get("content-type") == "application/json", "Should return JSON"
    data = response.json()
    assert "maintenance" in data or "error" in data, "Should indicate maintenance in response"
    assert "Retry-After" in response.headers, "Should include Retry-After header"
    print(f"Response: {data}")
    
    # Test /api/register
    response = client.post("/api/register", json={
        "name": "TestAgent",
        "model": "Test-1",
        "operator": "Test",
        "purpose": "Testing"
    })
    print(f"POST /api/register status: {response.status_code}")
    assert response.status_code == 503, "Register should be blocked in maintenance mode"
    data = response.json()
    assert "maintenance" in data or "error" in data, "Should indicate maintenance"
    
    # Test /.well-known/agents.txt
    response = client.get("/.well-known/agents.txt")
    print(f"GET /.well-known/agents.txt status: {response.status_code}")
    assert response.status_code == 503, "Well-known routes should return 503"
    
    # Test /openapi-agent.json
    response = client.get("/openapi-agent.json")
    print(f"GET /openapi-agent.json status: {response.status_code}")
    assert response.status_code == 503, "OpenAPI should return 503"
    
    # Test /mcp
    response = client.post("/mcp", json={"jsonrpc": "2.0", "method": "test", "id": 1})
    print(f"POST /mcp status: {response.status_code}")
    assert response.status_code == 503, "MCP should return 503"
    
    print("✓ Maintenance mode blocks API routes with JSON 503")


def test_maintenance_mode_allows_health():
    """Test that /health endpoint continues to work during maintenance"""
    print("\n=== Testing maintenance mode health check ===")
    
    # Enable maintenance mode
    os.environ['MAINTENANCE_MODE'] = 'YES'
    
    # Reimport
    import importlib
    import app.main
    importlib.reload(app.main)
    from app.main import app as reloaded_app
    
    client = TestClient(reloaded_app)
    
    # Test health endpoint
    response = client.get("/health")
    print(f"GET /health status: {response.status_code}")
    assert response.status_code == 200, "Health should work during maintenance for Fly.io monitoring"
    data = response.json()
    assert data.get("status") == "ok", "Health should return ok status"
    print(f"Health response: {data}")
    
    print("✓ Health check continues to work during maintenance")


def test_maintenance_mode_env_variants():
    """Test that various truthy env values enable maintenance mode"""
    print("\n=== Testing maintenance mode env variants ===")
    
    truthy_values = ["1", "true", "True", "TRUE", "yes", "YES", "Yes", "on", "ON"]
    
    import importlib
    import app.main
    
    for value in truthy_values:
        os.environ['MAINTENANCE_MODE'] = value
        importlib.reload(app.main)
        from app.main import is_maintenance_mode
        assert is_maintenance_mode(), f"'{value}' should enable maintenance mode"
        print(f"✓ '{value}' enables maintenance mode")
    
    # Test falsy values
    falsy_values = ["", "0", "false", "False", "no", "off", "disabled"]
    
    for value in falsy_values:
        os.environ['MAINTENANCE_MODE'] = value
        importlib.reload(app.main)
        from app.main import is_maintenance_mode
        assert not is_maintenance_mode(), f"'{value}' should NOT enable maintenance mode"
        print(f"✓ '{value}' does NOT enable maintenance mode")
    
    print("✓ All env variant tests passed")


if __name__ == "__main__":
    test_normal_mode_allows_traffic()
    test_maintenance_mode_blocks_html_routes()
    test_maintenance_mode_blocks_api_routes()
    test_maintenance_mode_allows_health()
    test_maintenance_mode_env_variants()
    print("\n" + "=" * 60)
    print("✓ ALL MAINTENANCE MODE TESTS PASSED")
    print("=" * 60)
