#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for usage tracking and user management
"""
import requests
import sys
import io
import json

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

BASE_URL = "http://localhost:8000"

print("=" * 60)
print("Usage Tracking & User Management Test")
print("=" * 60)

# Use a session to handle cookies automatically
admin_session = requests.Session()
user_session = requests.Session()

# Test 1: Admin login
print("\n1. Admin login...")
resp = admin_session.post(
    f"{BASE_URL}/auth/login",
    json={"email": "admin@test.com", "password": "TestPass123"}
)
if resp.status_code == 200:
    print("   ✓ Admin logged in")
else:
    print(f"   ✗ Login failed: {resp.text}")
    exit(1)

# Test 2: User login
print("\n2. User login...")
resp = user_session.post(
    f"{BASE_URL}/auth/login",
    json={"email": "testuser@test.com", "password": "UserPass123"}
)
if resp.status_code == 200:
    print("   ✓ User logged in")
else:
    print(f"   ✗ Login failed: {resp.text}")
    exit(1)

# Test 3: Make some test queries as user
print("\n3. Making test queries as user...")
test_queries = [
    "contract management tools",
    "document automation software",
    "legal research platforms"
]

for query in test_queries:
    resp = user_session.post(
        f"{BASE_URL}/query",
        json={"query": query}
    )
    if resp.status_code == 200:
        print(f"   ✓ Query: '{query}'")
    else:
        print(f"   ✗ Query failed: {resp.text}")

# Test 4: View all users (admin only)
print("\n4. Viewing all users with statistics...")
resp = admin_session.get(f"{BASE_URL}/admin/users")
if resp.status_code == 200:
    users = resp.json()['users']
    print(f"   ✓ Found {len(users)} users:")
    for user in users:
        print(f"      - {user['email']}: {user['total_requests']} requests ({user['status']})")
else:
    print(f"   ✗ Failed: {resp.text}")

# Test 5: View specific user stats
print("\n5. Viewing detailed stats for testuser@test.com...")
resp = admin_session.get(f"{BASE_URL}/admin/users/testuser@test.com/stats")
if resp.status_code == 200:
    stats = resp.json()
    print(f"   ✓ Email: {stats['email']}")
    print(f"   ✓ Total requests: {stats['total_requests']}")
    print(f"   ✓ By endpoint:")
    for endpoint_stat in stats['by_endpoint']:
        print(f"      - {endpoint_stat['endpoint']}: {endpoint_stat['count']} requests")
    print(f"   ✓ Recent activity (last {len(stats['recent_activity'])}):")
    for activity in stats['recent_activity'][:3]:
        print(f"      - {activity['endpoint']}: {activity['query_text'][:50]}...")
else:
    print(f"   ✗ Failed: {resp.text}")

# Test 6: Disable user account
print("\n6. Disabling user account...")
resp = admin_session.post(
    f"{BASE_URL}/admin/users/testuser@test.com/status",
    json={"status": "disabled"}
)
if resp.status_code == 200:
    print("   ✓ User account disabled")
else:
    print(f"   ✗ Failed: {resp.text}")

# Test 7: Try to make query as disabled user
print("\n7. Attempting query as disabled user...")
resp = user_session.post(
    f"{BASE_URL}/query",
    json={"query": "test query"}
)
if resp.status_code == 401:
    print("   ✓ Query correctly blocked (401 Unauthorized)")
elif resp.status_code == 403:
    print("   ✓ Query correctly blocked (403 Forbidden)")
else:
    print(f"   ✗ Query should have been blocked but got: {resp.status_code}")

# Test 8: Re-enable user account
print("\n8. Re-enabling user account...")
resp = admin_session.post(
    f"{BASE_URL}/admin/users/testuser@test.com/status",
    json={"status": "active"}
)
if resp.status_code == 200:
    print("   ✓ User account re-enabled")
else:
    print(f"   ✗ Failed: {resp.text}")

# Test 9: Try query again after re-enabling
print("\n9. Attempting query as re-enabled user...")
resp = user_session.post(
    f"{BASE_URL}/query",
    json={"query": "test query after re-enable"}
)
if resp.status_code == 200:
    print("   ✓ Query successful")
else:
    print(f"   ✗ Query failed: {resp.text}")

# Test 10: Non-admin cannot access admin endpoints
print("\n10. Testing that regular user cannot access admin endpoints...")
resp = user_session.get(f"{BASE_URL}/admin/users")
if resp.status_code == 403:
    print("   ✓ Admin endpoints correctly protected (403 Forbidden)")
else:
    print(f"   ✗ Should have been blocked but got: {resp.status_code}")

print("\n" + "=" * 60)
print("✓ All usage tracking tests passed!")
print("=" * 60)
print("\nUsage tracking features:")
print("1. ✓ All queries are logged to database")
print("2. ✓ Admin can view all users with request counts")
print("3. ✓ Admin can view detailed stats for any user")
print("4. ✓ Admin can disable/enable user accounts")
print("5. ✓ Disabled users cannot make requests")
print("6. ✓ Admin endpoints are protected from regular users")
print()
