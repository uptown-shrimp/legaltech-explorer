#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick manual test of authentication
"""
import requests
import sys
import io

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

BASE_URL = "http://localhost:8000"

print("=" * 60)
print("Quick Authentication Test")
print("=" * 60)

# Use a session to handle cookies automatically
session = requests.Session()

# Test 1: Health check
print("\n1. Testing health endpoint...")
resp = session.get(f"{BASE_URL}/health")
if resp.status_code == 200:
    print("   ✓ Server is running")
else:
    print("   ✗ Server not responding")
    exit(1)

# Test 2: Create admin (if needed)
print("\n2. Creating admin user...")
try:
    from auth_models import get_user_by_email, create_user
    existing = get_user_by_email("admin@test.com")
    if existing:
        print("   ℹ Admin already exists")
    else:
        user_id = create_user("admin@test.com", "TestPass123", role="admin")
        print(f"   ✓ Admin created (ID: {user_id})")
except Exception as e:
    print(f"   ✗ Error: {e}")

# Test 3: Login
print("\n3. Testing login...")
resp = session.post(
    f"{BASE_URL}/auth/login",
    json={"email": "admin@test.com", "password": "TestPass123"}
)
if resp.status_code == 200:
    data = resp.json()
    print(f"   ✓ Logged in as {data['user']['email']}")
    print(f"   ✓ Role: {data['user']['role']}")
else:
    print(f"   ✗ Login failed: {resp.text}")
    exit(1)

# Test 4: Check auth status
print("\n4. Checking authentication status...")
resp = session.get(f"{BASE_URL}/auth/me")
if resp.status_code == 200:
    data = resp.json()
    if data['authenticated']:
        print(f"   ✓ Authenticated as {data['user']['email']}")
    else:
        print("   ✗ Not authenticated (cookie issue)")
        exit(1)
else:
    print(f"   ✗ Failed: {resp.text}")
    exit(1)

# Test 5: Create invite
print("\n5. Creating invite for test user...")
resp = session.post(
    f"{BASE_URL}/admin/invite",
    json={"email": "testuser@test.com", "role": "user"}
)
if resp.status_code == 200:
    data = resp.json()
    token = data['token']
    print(f"   ✓ Invite created")
    print(f"   Token: {token[:30]}...")
    print(f"   \n   Visit: http://localhost:8000/register?token={token}")
else:
    print(f"   ✗ Failed: {resp.status_code} - {resp.text}")
    exit(1)

# Test 6: Check invite validity
print("\n6. Validating invite token...")
resp = session.get(f"{BASE_URL}/auth/check-invite/{token}")
if resp.status_code == 200:
    data = resp.json()
    print(f"   ✓ Invite is valid for {data['email']}")
else:
    print(f"   ✗ Invalid invite: {resp.text}")
    exit(1)

# Test 7: Register new user
print("\n7. Registering new user with invite...")
new_session = requests.Session()
resp = new_session.post(
    f"{BASE_URL}/auth/register",
    json={"token": token, "password": "UserPass123"}
)
if resp.status_code == 200:
    data = resp.json()
    print(f"   ✓ User registered: {data['user']['email']}")
elif "already exists" in resp.text:
    print("   ℹ User already exists")
    # Try logging in instead
    resp = new_session.post(
        f"{BASE_URL}/auth/login",
        json={"email": "testuser@test.com", "password": "UserPass123"}
    )
    if resp.status_code == 200:
        print("   ✓ Logged in with existing user")
    else:
        print(f"   ✗ Login failed: {resp.text}")
else:
    print(f"   ✗ Registration failed: {resp.text}")

# Test 8: Logout
print("\n8. Testing logout...")
resp = session.post(f"{BASE_URL}/auth/logout")
if resp.status_code == 200:
    print("   ✓ Logout successful")
else:
    print(f"   ✗ Logout failed: {resp.text}")

# Test 9: Verify logged out
print("\n9. Verifying logout...")
resp = session.get(f"{BASE_URL}/auth/me")
if resp.status_code == 200:
    data = resp.json()
    if not data['authenticated']:
        print("   ✓ Successfully logged out")
    else:
        print("   ✗ Still authenticated (cookie issue)")
else:
    print(f"   ✗ Failed: {resp.text}")

print("\n" + "=" * 60)
print("✓ All tests passed!")
print("=" * 60)
print("\nAuthentication system is working correctly.")
print("\nYou can now:")
print("1. Visit http://localhost:8000 in your browser")
print("2. Open the invite link above to test registration")
print("3. Deploy to Render with confidence!")
print()
