# auth_models.py
"""
Authentication and user management models
Supports both SQLite (local dev) and PostgreSQL (production)
"""
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional
from passlib.context import CryptContext
from contextlib import contextmanager

# Password hashing configuration (using bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database configuration
# If DATABASE_URL is set (Render PostgreSQL), use PostgreSQL
# Otherwise fall back to SQLite for local development
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    # PostgreSQL mode
    import psycopg2
    from psycopg2.extras import RealDictCursor

    # Fix for Render's postgres:// URL (psycopg2 requires postgresql://)
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

    DB_TYPE = "postgresql"
else:
    # SQLite mode (local development)
    import sqlite3
    DB_TYPE = "sqlite"
    DB_FILE = os.getenv("AUTH_DB_FILE", "auth.db")


@contextmanager
def get_db():
    """Get database connection with context manager"""
    if DB_TYPE == "postgresql":
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def _get_placeholder():
    """Get the correct placeholder for the database type"""
    return "%s" if DB_TYPE == "postgresql" else "?"


def init_db():
    """Initialize database tables"""
    ph = _get_placeholder()

    if DB_TYPE == "postgresql":
        # PostgreSQL schema
        users_table = """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                client_id TEXT,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """
        invites_table = """
            CREATE TABLE IF NOT EXISTS invites (
                id SERIAL PRIMARY KEY,
                token TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                client_id TEXT,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP
            )
        """
        sessions_table = """
            CREATE TABLE IF NOT EXISTS sessions (
                id SERIAL PRIMARY KEY,
                session_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id),
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        usage_logs_table = """
            CREATE TABLE IF NOT EXISTS usage_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                user_email TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                query_text TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
    else:
        # SQLite schema
        users_table = """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                client_id TEXT,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """
        invites_table = """
            CREATE TABLE IF NOT EXISTS invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                client_id TEXT,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_at TIMESTAMP
            )
        """
        sessions_table = """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """
        usage_logs_table = """
            CREATE TABLE IF NOT EXISTS usage_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                user_email TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                query_text TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(users_table)
        cursor.execute(invites_table)
        cursor.execute(sessions_table)
        cursor.execute(usage_logs_table)


# ===== Password Hashing =====
def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)


# ===== User Management =====
def create_user(email: str, password: str, role: str = "user", client_id: Optional[str] = None) -> Optional[int]:
    """Create a new user"""
    ph = _get_placeholder()
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            password_hash = hash_password(password)

            if DB_TYPE == "postgresql":
                cursor.execute(f"""
                    INSERT INTO users (email, password_hash, role, client_id)
                    VALUES ({ph}, {ph}, {ph}, {ph})
                    RETURNING id
                """, (email, password_hash, role, client_id))
                result = cursor.fetchone()
                return result['id'] if result else None
            else:
                cursor.execute(f"""
                    INSERT INTO users (email, password_hash, role, client_id)
                    VALUES ({ph}, {ph}, {ph}, {ph})
                """, (email, password_hash, role, client_id))
                return cursor.lastrowid
    except Exception as e:
        print(f"Error creating user: {e}")
        return None


def get_user_by_email(email: str) -> Optional[dict]:
    """Get user by email"""
    ph = _get_placeholder()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE email = {ph}", (email,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def get_user_by_id(user_id: int) -> Optional[dict]:
    """Get user by ID"""
    ph = _get_placeholder()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE id = {ph}", (user_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def update_last_login(user_id: int):
    """Update user's last login timestamp"""
    ph = _get_placeholder()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            UPDATE users
            SET last_login = CURRENT_TIMESTAMP
            WHERE id = {ph}
        """, (user_id,))


def authenticate_user(email: str, password: str) -> Optional[dict]:
    """Authenticate user with email and password"""
    user = get_user_by_email(email)

    if not user:
        return None

    if user['status'] != 'active':
        return None

    if not verify_password(password, user['password_hash']):
        return None

    update_last_login(user['id'])
    return user


# ===== Invite Management =====
def create_invite(email: str, role: str = "user", client_id: Optional[str] = None, expires_hours: int = 72) -> str:
    """Create a new invite token"""
    ph = _get_placeholder()
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=expires_hours)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            INSERT INTO invites (token, email, role, client_id, expires_at)
            VALUES ({ph}, {ph}, {ph}, {ph}, {ph})
        """, (token, email, role, client_id, expires_at))

    return token


def get_invite(token: str) -> Optional[dict]:
    """Get invite by token"""
    ph = _get_placeholder()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM invites WHERE token = {ph}", (token,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def validate_invite(token: str) -> Optional[dict]:
    """Validate an invite token (not expired, not used)"""
    invite = get_invite(token)

    if not invite:
        return None

    if invite['used']:
        return None

    expires_at = invite['expires_at']
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)

    if datetime.utcnow() > expires_at:
        return None

    return invite


def mark_invite_used(token: str):
    """Mark an invite as used"""
    ph = _get_placeholder()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            UPDATE invites
            SET used = TRUE, used_at = CURRENT_TIMESTAMP
            WHERE token = {ph}
        """, (token,))


# ===== Session Management =====
def create_session(user_id: int, expires_hours: int = 24) -> str:
    """Create a new session"""
    ph = _get_placeholder()
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=expires_hours)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            INSERT INTO sessions (session_id, user_id, expires_at)
            VALUES ({ph}, {ph}, {ph})
        """, (session_id, user_id, expires_at))

    return session_id


def get_session(session_id: str) -> Optional[dict]:
    """Get session by ID"""
    ph = _get_placeholder()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM sessions WHERE session_id = {ph}", (session_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None


def validate_session(session_id: str) -> Optional[dict]:
    """Validate a session and return the user if valid"""
    session = get_session(session_id)

    if not session:
        return None

    expires_at = session['expires_at']
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)

    if datetime.utcnow() > expires_at:
        return None

    user = get_user_by_id(session['user_id'])

    if not user or user['status'] != 'active':
        return None

    return user


def delete_session(session_id: str):
    """Delete a session (logout)"""
    ph = _get_placeholder()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM sessions WHERE session_id = {ph}", (session_id,))


def cleanup_expired_sessions():
    """Remove expired sessions"""
    with get_db() as conn:
        cursor = conn.cursor()
        if DB_TYPE == "postgresql":
            cursor.execute("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP")
        else:
            cursor.execute(f"DELETE FROM sessions WHERE expires_at < ?", (datetime.utcnow().isoformat(),))


# ===== Usage Tracking =====
def log_usage(user_id: int, user_email: str, endpoint: str, query_text: Optional[str] = None):
    """Log a user action"""
    ph = _get_placeholder()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            INSERT INTO usage_logs (user_id, user_email, endpoint, query_text)
            VALUES ({ph}, {ph}, {ph}, {ph})
        """, (user_id, user_email, endpoint, query_text))


def get_user_stats(user_email: str) -> dict:
    """Get usage statistics for a specific user"""
    ph = _get_placeholder()
    with get_db() as conn:
        cursor = conn.cursor()

        # Get total requests
        cursor.execute(f"""
            SELECT COUNT(*) as total_requests
            FROM usage_logs
            WHERE user_email = {ph}
        """, (user_email,))
        row = cursor.fetchone()
        total = row['total_requests'] if row else 0

        # Get requests by endpoint
        cursor.execute(f"""
            SELECT endpoint, COUNT(*) as count
            FROM usage_logs
            WHERE user_email = {ph}
            GROUP BY endpoint
            ORDER BY count DESC
        """, (user_email,))
        by_endpoint = [dict(row) for row in cursor.fetchall()]

        # Get recent activity (last 10)
        cursor.execute(f"""
            SELECT endpoint, query_text, created_at
            FROM usage_logs
            WHERE user_email = {ph}
            ORDER BY created_at DESC
            LIMIT 10
        """, (user_email,))
        recent_activity = [dict(row) for row in cursor.fetchall()]

        return {
            'email': user_email,
            'total_requests': total,
            'by_endpoint': by_endpoint,
            'recent_activity': recent_activity
        }


def get_all_users_stats() -> list:
    """Get usage statistics for all users"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                u.id,
                u.email,
                u.role,
                u.status,
                u.created_at,
                u.last_login,
                COUNT(l.id) as total_requests
            FROM users u
            LEFT JOIN usage_logs l ON u.id = l.user_id
            GROUP BY u.id, u.email, u.role, u.status, u.created_at, u.last_login
            ORDER BY total_requests DESC
        """)
        users = [dict(row) for row in cursor.fetchall()]
        return users


def set_user_status(email: str, status: str) -> bool:
    """Enable or disable a user account"""
    if status not in ['active', 'disabled']:
        return False

    ph = _get_placeholder()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            UPDATE users
            SET status = {ph}
            WHERE email = {ph}
        """, (status, email))

        return cursor.rowcount > 0


def reset_password(email: str, new_password: str) -> bool:
    """Reset a user's password"""
    ph = _get_placeholder()
    password_hash = hash_password(new_password)

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            UPDATE users
            SET password_hash = {ph}
            WHERE email = {ph}
        """, (password_hash, email))

        return cursor.rowcount > 0


# Initialize database on import
init_db()

# Print database type for debugging
print(f"[Auth] Using {DB_TYPE.upper()} database")
