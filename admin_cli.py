#!/usr/bin/env python3
"""
Admin CLI tool for managing users and invites
Usage:
    python admin_cli.py create-invite email@example.com
    python admin_cli.py create-invite email@example.com --role admin
    python admin_cli.py create-admin admin@example.com password123
    python admin_cli.py create-user user@example.com password123
"""
import sys
import argparse
from auth_models import create_invite, create_user, get_user_by_email

def create_invite_cmd(email: str, role: str = "user", client_id: str = None):
    """Create an invite link"""
    token = create_invite(email=email, role=role, client_id=client_id)

    print(f"\n✓ Invite created successfully!")
    print(f"  Email: {email}")
    print(f"  Role: {role}")
    if client_id:
        print(f"  Client ID: {client_id}")
    print(f"\n  Token: {token}")
    print(f"\n  Invite URL:")
    print(f"  https://your-domain.com/register?token={token}")
    print(f"\n  This invite will expire in 72 hours.\n")

def create_admin_cmd(email: str, password: str):
    """Create an admin user directly"""
    existing = get_user_by_email(email)
    if existing:
        print(f"✗ Error: User with email {email} already exists")
        sys.exit(1)

    user_id = create_user(email=email, password=password, role="admin")

    if user_id:
        print(f"\n✓ Admin user created successfully!")
        print(f"  Email: {email}")
        print(f"  User ID: {user_id}")
        print(f"\n  You can now login with these credentials.\n")
    else:
        print(f"✗ Error: Failed to create admin user")
        sys.exit(1)

def create_user_cmd(email: str, password: str):
    """Create a regular user directly"""
    existing = get_user_by_email(email)
    if existing:
        print(f"✗ Error: User with email {email} already exists")
        sys.exit(1)

    user_id = create_user(email=email, password=password, role="user")

    if user_id:
        print(f"\n✓ User created successfully!")
        print(f"  Email: {email}")
        print(f"  Role: user")
        print(f"  User ID: {user_id}")
        print(f"\n  User can now login with these credentials.\n")
    else:
        print(f"✗ Error: Failed to create user")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Admin CLI for Legal-Tech Explorer")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Create invite command
    invite_parser = subparsers.add_parser("create-invite", help="Create an invite link")
    invite_parser.add_argument("email", help="Email address for the invite")
    invite_parser.add_argument("--role", default="user", choices=["user", "admin"], help="User role")
    invite_parser.add_argument("--client-id", help="Client ID (optional)")

    # Create admin command
    admin_parser = subparsers.add_parser("create-admin", help="Create an admin user")
    admin_parser.add_argument("email", help="Admin email address")
    admin_parser.add_argument("password", help="Admin password")

    # Create user command
    user_parser = subparsers.add_parser("create-user", help="Create a regular user")
    user_parser.add_argument("email", help="User email address")
    user_parser.add_argument("password", help="User password")

    args = parser.parse_args()

    if args.command == "create-invite":
        create_invite_cmd(args.email, args.role, args.client_id)
    elif args.command == "create-admin":
        create_admin_cmd(args.email, args.password)
    elif args.command == "create-user":
        create_user_cmd(args.email, args.password)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
