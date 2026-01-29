#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Authentication system test script
Tests all endpoints without needing a browser
"""
import requests
import json
import sys
import io

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

from admin_cli import create_admin_cmd, create_invite_cmd

BASE_URL = "http://localhost:8000"

def test_health():
    """Test health endpoint"""
    print("\n1. Testing health endpoint...")
    try:
        resp = requests.get(f"{BASE_URL}/health")
        assert resp.status_code == 200
        print("   ✓ Health check passed")
        return True
    except Exception as e:
        print(f"   ✗ Health check failed: {e}")
        return False

def test_auth_me_anonymous():
    """Test /auth/me when not logged in"""
    print("\n2. Testing anonymous auth status...")
    try:
        resp = requests.get(f"{BASE_URL}/auth/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data['authenticated'] == False
        print("   ✓ Anonymous user correctly not authenticated")
        return True
    except Exception as e:
        print(f"   ✗ Test failed: {e}")
        return False

def test_create_admin():
    """Create test admin user"""
    print("\n3. Creating test admin user...")
    try:
        from auth_models import get_user_by_email, create_user

        # Check if admin exists
        existing = get_user_by_email("admin@test.com")
        if existing:
            print("   ℹ Admin user already exists, skipping creation")
            return True

        # Create admin
        user_id = create_user("admin@test.com", "TestPass123", role="admin")
        if user_id:
            print(f"   ✓ Admin user created (ID: {user_id})")
            return True
        else:
            print("   ✗ Failed to create admin")
            return False
    except Exception as e:
        print(f"   ✗ Test failed: {e}")
        return False

def test_login(email="admin@test.com", password="TestPass123"):
    """Test login endpoint"""
    print(f"\n4. Testing login with {email}...")
    try:
        resp = requests.post(
            f"{BASE_URL}/auth/login",
            json={"email": email, "password": password}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data['success'] == True
        assert data['user']['email'] == email

        # Check cookies
        assert 'session_id' in resp.cookies

        print(f"   ✓ Login successful for {email}")
        return resp.cookies
    except AssertionError as e:
        print(f"   ✗ Login failed: {resp.status_code} - {resp.text}")
        return None
    except Exception as e:
        print(f"   ✗ Test failed: {e}")
        return None

def test_auth_me_authenticated(cookies):
    """Test /auth/me when logged in"""
    print("\n5. Testing authenticated auth status...")
    try:
        resp = requests.get(f"{BASE_URL}/auth/me", cookies=cookies)
        assert resp.status_code == 200
        data = resp.json()
        assert data['authenticated'] == True
        assert 'user' in data
        print(f"   ✓ Authenticated as {data['user']['email']}")
        return True
    except Exception as e:
        print(f"   ✗ Test failed: {e}")
        return False

def test_create_invite(cookies):
    """Test creating an invite (admin only)"""
    print("\n6. Testing invite creation (admin endpoint)...")
    try:
        resp = requests.post(
            f"{BASE_URL}/admin/invite",
            json={"email": "testuser@test.com", "role": "user"},
            cookies=cookies
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data['success'] == True
        assert 'token' in data

        token = data['token']
        print(f"   ✓ Invite created")
        print(f"     Token: {token[:20]}...")
        return token
    except Exception as e:
        print(f"   ✗ Test failed: {e}")
        print(f"     Response: {resp.text}")
        return None

def test_check_invite(token):
    """Test checking invite validity"""
    print("\n7. Testing invite validation...")
    try:
        resp = requests.get(f"{BASE_URL}/auth/check-invite/{token}")
        assert resp.status_code == 200
        data = resp.json()
        assert data['valid'] == True
        assert data['email'] == "testuser@test.com"
        print(f"   ✓ Invite is valid for {data['email']}")
        return True
    except Exception as e:
        print(f"   ✗ Test failed: {e}")
        return False

def test_register(token):
    """Test user registration with invite"""
    print("\n8. Testing user registration...")
    try:
        resp = requests.post(
            f"{BASE_URL}/auth/register",
            json={"token": token, "password": "UserPass123"}
        )

        if resp.status_code == 400 and "already exists" in resp.text:
            print("   ℹ User already exists, skipping registration")
            # Try logging in instead
            return test_login("testuser@test.com", "UserPass123")

        assert resp.status_code == 200
        data = resp.json()
        assert data['success'] == True
        assert data['user']['email'] == "testuser@test.com"

        print(f"   ✓ User registered successfully")
        return resp.cookies
    except Exception as e:
        print(f"   ✗ Test failed: {e}")
        print(f"     Response: {resp.text}")
        return None

def test_logout(cookies):
    """Test logout"""
    print("\n9. Testing logout...")
    try:
        resp = requests.post(f"{BASE_URL}/auth/logout", cookies=cookies)
        assert resp.status_code == 200
        data = resp.json()
        assert data['success'] == True
        print("   ✓ Logout successful")
        return True
    except Exception as e:
        print(f"   ✗ Test failed: {e}")
        return False

def test_non_admin_cannot_create_invite():
    """Test that non-admin users cannot create invites"""
    print("\n10. Testing non-admin cannot create invites...")
    try:
        # Login as regular user
        user_cookies = test_login("testuser@test.com", "UserPass123")
        if not user_cookies:
            print("   ⚠ Skipped (user doesn't exist)")
            return True

        # Try to create invite
        resp = requests.post(
            f"{BASE_URL}/admin/invite",
            json={"email": "another@test.com", "role": "user"},
            cookies=user_cookies
        )

        assert resp.status_code == 403  # Forbidden
        print("   ✓ Non-admin correctly blocked from creating invites")
        return True
    except Exception as e:
        print(f"   ✗ Test failed: {e}")
        return False

def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("Authentication System Test Suite")
    print("=" * 60)
    print(f"\nTesting against: {BASE_URL}")
    print("Make sure the server is running: uvicorn ai_search_api:app --reload")

    results = []

    # Test 1: Health
    results.append(test_health())

    # Test 2: Anonymous auth
    results.append(test_auth_me_anonymous())

    # Test 3: Create admin
    results.append(test_create_admin())

    # Test 4: Login as admin
    admin_cookies = test_login()
    results.append(admin_cookies is not None)

    if not admin_cookies:
        print("\n✗ Cannot continue tests without admin login")
        return

    # Test 5: Check authenticated status
    results.append(test_auth_me_authenticated(admin_cookies))

    # Test 6: Create invite
    token = test_create_invite(admin_cookies)
    results.append(token is not None)

    if not token:
        print("\n✗ Cannot continue tests without invite token")
        return

    # Test 7: Check invite validity
    results.append(test_check_invite(token))

    # Test 8: Register user
    user_cookies = test_register(token)
    results.append(user_cookies is not None)

    # Test 9: Logout
    if user_cookies:
        results.append(test_logout(user_cookies))

    # Test 10: Non-admin authorization
    results.append(test_non_admin_cannot_create_invite())

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"\nPassed: {passed}/{total}")

    if passed == total:
        print("\n✓ All tests passed! Authentication system is working correctly.")
        print("\nYou can now safely deploy to Render.")
    else:
        print(f"\n✗ {total - passed} test(s) failed. Please fix before deploying.")
        sys.exit(1)

if __name__ == "__main__":
    try:
        run_all_tests()
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
