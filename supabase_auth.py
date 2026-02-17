# supabase_auth.py
"""
Supabase Authentication module
Handles user authentication via Supabase Auth
"""
import os
from typing import Optional
from supabase import create_client, Client

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

# Initialize Supabase clients
# Public client for user-facing operations
supabase: Optional[Client] = None
# Admin client for server-side operations (bypasses RLS)
supabase_admin: Optional[Client] = None

if SUPABASE_URL and SUPABASE_ANON_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    print("[Auth] Supabase client initialized")
else:
    print("[Auth] Warning: Supabase credentials not found")

if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    print("[Auth] Supabase admin client initialized")


def is_configured() -> bool:
    """Check if Supabase is properly configured"""
    return supabase is not None and supabase_admin is not None


# ===== User Authentication =====

def sign_up(email: str, password: str) -> dict:
    """
    Sign up a new user with email and password
    Returns: {"user": {...}, "session": {...}} or {"error": "..."}
    """
    if not supabase:
        return {"error": "Supabase not configured"}

    try:
        response = supabase.auth.sign_up({
            "email": email,
            "password": password
        })

        if response.user:
            return {
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                    "created_at": str(response.user.created_at)
                },
                "session": {
                    "access_token": response.session.access_token if response.session else None,
                    "refresh_token": response.session.refresh_token if response.session else None
                } if response.session else None
            }
        else:
            return {"error": "Sign up failed"}
    except Exception as e:
        return {"error": str(e)}


def sign_in(email: str, password: str) -> dict:
    """
    Sign in a user with email and password
    Returns: {"user": {...}, "session": {...}} or {"error": "..."}
    """
    if not supabase:
        return {"error": "Supabase not configured"}

    try:
        response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })

        if response.user and response.session:
            return {
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                    "role": response.user.role,
                    "created_at": str(response.user.created_at)
                },
                "session": {
                    "access_token": response.session.access_token,
                    "refresh_token": response.session.refresh_token,
                    "expires_at": response.session.expires_at
                }
            }
        else:
            return {"error": "Invalid credentials"}
    except Exception as e:
        error_msg = str(e)
        if "Invalid login credentials" in error_msg:
            return {"error": "Invalid email or password"}
        return {"error": error_msg}


def sign_out(access_token: str) -> dict:
    """
    Sign out a user
    Returns: {"success": True} or {"error": "..."}
    """
    if not supabase:
        return {"error": "Supabase not configured"}

    try:
        # Set the session before signing out
        supabase.auth.sign_out()
        return {"success": True}
    except Exception as e:
        return {"error": str(e)}


def get_user_from_token(access_token: str) -> Optional[dict]:
    """
    Validate an access token and return user info
    Returns: {"id": ..., "email": ..., "role": ...} or None
    """
    if not supabase:
        return None

    try:
        response = supabase.auth.get_user(access_token)

        if response and response.user:
            # Get user metadata for role
            user_metadata = response.user.user_metadata or {}
            app_metadata = response.user.app_metadata or {}

            return {
                "id": response.user.id,
                "email": response.user.email,
                "role": app_metadata.get("role", user_metadata.get("role", "user")),
                "created_at": str(response.user.created_at)
            }
        return None
    except Exception as e:
        print(f"[Auth] Token validation error: {e}")
        return None


def refresh_session(refresh_token: str) -> dict:
    """
    Refresh an expired session
    Returns: {"session": {...}} or {"error": "..."}
    """
    if not supabase:
        return {"error": "Supabase not configured"}

    try:
        response = supabase.auth.refresh_session(refresh_token)

        if response.session:
            return {
                "session": {
                    "access_token": response.session.access_token,
                    "refresh_token": response.session.refresh_token,
                    "expires_at": response.session.expires_at
                }
            }
        return {"error": "Failed to refresh session"}
    except Exception as e:
        return {"error": str(e)}


# ===== Password Reset =====

def request_password_reset(email: str, redirect_url: str) -> dict:
    """
    Send a password reset email
    Returns: {"success": True} or {"error": "..."}
    """
    if not supabase:
        return {"error": "Supabase not configured"}

    try:
        supabase.auth.reset_password_email(
            email,
            options={"redirect_to": redirect_url}
        )
        return {"success": True}
    except Exception as e:
        return {"error": str(e)}


def update_password(access_token: str, new_password: str) -> dict:
    """
    Update user's password (requires valid session)
    Returns: {"success": True} or {"error": "..."}
    """
    if not supabase:
        return {"error": "Supabase not configured"}

    try:
        # This requires the user to be authenticated
        response = supabase.auth.update_user({
            "password": new_password
        })

        if response.user:
            return {"success": True}
        return {"error": "Failed to update password"}
    except Exception as e:
        return {"error": str(e)}


# ===== Admin Operations (Server-side only) =====

def admin_create_user(email: str, password: str, role: str = "user") -> dict:
    """
    Create a user directly (admin operation)
    Returns: {"user": {...}} or {"error": "..."}
    """
    if not supabase_admin:
        return {"error": "Supabase admin not configured"}

    try:
        response = supabase_admin.auth.admin.create_user({
            "email": email,
            "password": password,
            "email_confirm": True,  # Auto-confirm email
            "app_metadata": {"role": role}
        })

        if response.user:
            return {
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                    "role": role
                }
            }
        return {"error": "Failed to create user"}
    except Exception as e:
        return {"error": str(e)}


def admin_invite_user(email: str, role: str = "user", redirect_url: str = None) -> dict:
    """
    Send an invite email to a user
    Returns: {"success": True} or {"error": "..."}
    """
    if not supabase_admin:
        return {"error": "Supabase admin not configured"}

    try:
        options = {
            "data": {"role": role}
        }
        if redirect_url:
            options["redirect_to"] = redirect_url

        response = supabase_admin.auth.admin.invite_user_by_email(
            email,
            options=options
        )

        if response.user:
            return {"success": True, "user_id": response.user.id}
        return {"error": "Failed to send invite"}
    except Exception as e:
        return {"error": str(e)}


def admin_delete_user(user_id: str) -> dict:
    """
    Delete a user (admin operation)
    Returns: {"success": True} or {"error": "..."}
    """
    if not supabase_admin:
        return {"error": "Supabase admin not configured"}

    try:
        supabase_admin.auth.admin.delete_user(user_id)
        return {"success": True}
    except Exception as e:
        return {"error": str(e)}


def admin_list_users() -> dict:
    """
    List all users (admin operation)
    Returns: {"users": [...]} or {"error": "..."}
    """
    if not supabase_admin:
        return {"error": "Supabase admin not configured"}

    try:
        response = supabase_admin.auth.admin.list_users()

        users = []
        for user in response:
            app_metadata = user.app_metadata or {}
            users.append({
                "id": user.id,
                "email": user.email,
                "role": app_metadata.get("role", "user"),
                "created_at": str(user.created_at),
                "last_sign_in": str(user.last_sign_in_at) if user.last_sign_in_at else None,
                "confirmed": user.email_confirmed_at is not None
            })

        return {"users": users}
    except Exception as e:
        return {"error": str(e)}


def admin_update_user_role(user_id: str, role: str) -> dict:
    """
    Update a user's role (admin operation)
    Returns: {"success": True} or {"error": "..."}
    """
    if not supabase_admin:
        return {"error": "Supabase admin not configured"}

    try:
        response = supabase_admin.auth.admin.update_user_by_id(
            user_id,
            {"app_metadata": {"role": role}}
        )

        if response.user:
            return {"success": True}
        return {"error": "Failed to update user"}
    except Exception as e:
        return {"error": str(e)}


# ===== Usage Tracking (Keep using PostgreSQL) =====
# Usage tracking remains in auth_models.py using your Render PostgreSQL
# This keeps your usage data separate from Supabase auth
