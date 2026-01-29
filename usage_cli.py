#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI tool for viewing usage statistics and managing users
Run this directly on the server (doesn't require API calls)
"""
import sys
import io
from datetime import datetime

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

from auth_models import get_all_users_stats, get_user_stats, set_user_status

def print_all_users():
    """Display all users with their usage statistics"""
    users = get_all_users_stats()

    print("\n" + "=" * 80)
    print("ALL USERS - USAGE STATISTICS")
    print("=" * 80)

    if not users:
        print("No users found.")
        return

    # Header
    print(f"\n{'Email':<35} {'Role':<10} {'Status':<10} {'Requests':<10} {'Last Login':<20}")
    print("-" * 80)

    for user in users:
        email = user['email'][:33] + '..' if len(user['email']) > 35 else user['email']
        role = user['role']
        status = user['status']
        requests = user['total_requests']
        last_login = user['last_login'] if user['last_login'] else 'Never'
        if last_login != 'Never':
            # Format timestamp
            try:
                dt = datetime.fromisoformat(last_login)
                last_login = dt.strftime('%Y-%m-%d %H:%M')
            except:
                pass

        print(f"{email:<35} {role:<10} {status:<10} {requests:<10} {last_login:<20}")

    print("\n")

def print_user_details(email):
    """Display detailed statistics for a specific user"""
    stats = get_user_stats(email)

    print("\n" + "=" * 80)
    print(f"USER DETAILS - {email}")
    print("=" * 80)

    print(f"\nTotal Requests: {stats['total_requests']}")

    print("\n--- Requests by Endpoint ---")
    if stats['by_endpoint']:
        for endpoint_stat in stats['by_endpoint']:
            print(f"  {endpoint_stat['endpoint']}: {endpoint_stat['count']} requests")
    else:
        print("  No activity yet")

    print("\n--- Recent Activity (Last 10) ---")
    if stats['recent_activity']:
        for activity in stats['recent_activity']:
            timestamp = activity['created_at']
            try:
                dt = datetime.fromisoformat(timestamp)
                timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                pass

            query = activity['query_text'] if activity['query_text'] else 'N/A'
            query_short = query[:60] + '...' if len(query) > 60 else query

            print(f"  [{timestamp}] {activity['endpoint']}")
            print(f"    Query: {query_short}")
    else:
        print("  No activity yet")

    print("\n")

def disable_user(email):
    """Disable a user account"""
    success = set_user_status(email, 'disabled')
    if success:
        print(f"\n✓ User '{email}' has been DISABLED")
    else:
        print(f"\n✗ User '{email}' not found")

def enable_user(email):
    """Enable a user account"""
    success = set_user_status(email, 'active')
    if success:
        print(f"\n✓ User '{email}' has been ENABLED")
    else:
        print(f"\n✗ User '{email}' not found")

def print_usage():
    """Print CLI usage instructions"""
    print("""
Usage Statistics CLI
====================

Commands:
  python usage_cli.py list
      List all users with usage statistics

  python usage_cli.py stats <email>
      Show detailed statistics for a specific user

  python usage_cli.py disable <email>
      Disable a user account (they won't be able to login)

  python usage_cli.py enable <email>
      Re-enable a disabled user account

Examples:
  python usage_cli.py list
  python usage_cli.py stats consultant@example.com
  python usage_cli.py disable consultant@example.com
  python usage_cli.py enable consultant@example.com
""")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "list":
        print_all_users()

    elif command == "stats":
        if len(sys.argv) < 3:
            print("\n✗ Error: Please provide an email address")
            print("Usage: python usage_cli.py stats <email>")
            sys.exit(1)
        email = sys.argv[2]
        print_user_details(email)

    elif command == "disable":
        if len(sys.argv) < 3:
            print("\n✗ Error: Please provide an email address")
            print("Usage: python usage_cli.py disable <email>")
            sys.exit(1)
        email = sys.argv[2]
        disable_user(email)

    elif command == "enable":
        if len(sys.argv) < 3:
            print("\n✗ Error: Please provide an email address")
            print("Usage: python usage_cli.py enable <email>")
            sys.exit(1)
        email = sys.argv[2]
        enable_user(email)

    else:
        print(f"\n✗ Error: Unknown command '{command}'")
        print_usage()
        sys.exit(1)
