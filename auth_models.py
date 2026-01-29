# auth_models.py
"""
Authentication and user management models
"""
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional
import sqlite3
from passlib.context import CryptContext

# Password hashing configuration (using bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database file
DB_FILE = os.getenv("AUTH_DB_FILE", "auth.db")

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables"""
    conn = get_db()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
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
    """)

    # Invites table
    cursor.execute("""
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
    """)

    # Sessions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Usage logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usage_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            user_email TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            query_text TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()

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
    try:
        conn = get_db()
        cursor = conn.cursor()

        password_hash = hash_password(password)

        cursor.execute("""
            INSERT INTO users (email, password_hash, role, client_id)
            VALUES (?, ?, ?, ?)
        """, (email, password_hash, role, client_id))

        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return user_id
    except sqlite3.IntegrityError:
        return None  # User already exists

def get_user_by_email(email: str) -> Optional[dict]:
    """Get user by email"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return dict(row)
    return None

def get_user_by_id(user_id: int) -> Optional[dict]:
    """Get user by ID"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return dict(row)
    return None

def update_last_login(user_id: int):
    """Update user's last login timestamp"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET last_login = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (user_id,))

    conn.commit()
    conn.close()

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
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=expires_hours)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO invites (token, email, role, client_id, expires_at)
        VALUES (?, ?, ?, ?, ?)
    """, (token, email, role, client_id, expires_at.isoformat()))

    conn.commit()
    conn.close()

    return token

def get_invite(token: str) -> Optional[dict]:
    """Get invite by token"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM invites WHERE token = ?", (token,))
    row = cursor.fetchone()
    conn.close()

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

    expires_at = datetime.fromisoformat(invite['expires_at'])
    if datetime.utcnow() > expires_at:
        return None

    return invite

def mark_invite_used(token: str):
    """Mark an invite as used"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE invites
        SET used = 1, used_at = CURRENT_TIMESTAMP
        WHERE token = ?
    """, (token,))

    conn.commit()
    conn.close()

# ===== Session Management =====
def create_session(user_id: int, expires_hours: int = 24) -> str:
    """Create a new session"""
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=expires_hours)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO sessions (session_id, user_id, expires_at)
        VALUES (?, ?, ?)
    """, (session_id, user_id, expires_at.isoformat()))

    conn.commit()
    conn.close()

    return session_id

def get_session(session_id: str) -> Optional[dict]:
    """Get session by ID"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return dict(row)
    return None

def validate_session(session_id: str) -> Optional[dict]:
    """Validate a session and return the user if valid"""
    session = get_session(session_id)

    if not session:
        return None

    expires_at = datetime.fromisoformat(session['expires_at'])
    if datetime.utcnow() > expires_at:
        return None

    user = get_user_by_id(session['user_id'])

    if not user or user['status'] != 'active':
        return None

    return user

def delete_session(session_id: str):
    """Delete a session (logout)"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))

    conn.commit()
    conn.close()

def cleanup_expired_sessions():
    """Remove expired sessions"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM sessions
        WHERE expires_at < ?
    """, (datetime.utcnow().isoformat(),))

    conn.commit()
    conn.close()

# ===== Usage Tracking =====
def log_usage(user_id: int, user_email: str, endpoint: str, query_text: Optional[str] = None):
    """Log a user action"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO usage_logs (user_id, user_email, endpoint, query_text)
        VALUES (?, ?, ?, ?)
    """, (user_id, user_email, endpoint, query_text))

    conn.commit()
    conn.close()

def get_user_stats(user_email: str) -> dict:
    """Get usage statistics for a specific user"""
    conn = get_db()
    cursor = conn.cursor()

    # Get total requests
    cursor.execute("""
        SELECT COUNT(*) as total_requests
        FROM usage_logs
        WHERE user_email = ?
    """, (user_email,))
    total = cursor.fetchone()['total_requests']

    # Get requests by endpoint
    cursor.execute("""
        SELECT endpoint, COUNT(*) as count
        FROM usage_logs
        WHERE user_email = ?
        GROUP BY endpoint
        ORDER BY count DESC
    """, (user_email,))
    by_endpoint = [dict(row) for row in cursor.fetchall()]

    # Get recent activity (last 10)
    cursor.execute("""
        SELECT endpoint, query_text, created_at
        FROM usage_logs
        WHERE user_email = ?
        ORDER BY created_at DESC
        LIMIT 10
    """, (user_email,))
    recent_activity = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        'email': user_email,
        'total_requests': total,
        'by_endpoint': by_endpoint,
        'recent_activity': recent_activity
    }

def get_all_users_stats() -> list:
    """Get usage statistics for all users"""
    conn = get_db()
    cursor = conn.cursor()

    # Get all users with request counts
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
        GROUP BY u.id
        ORDER BY total_requests DESC
    """)
    users = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return users

def set_user_status(email: str, status: str) -> bool:
    """Enable or disable a user account"""
    if status not in ['active', 'disabled']:
        return False

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE users
        SET status = ?
        WHERE email = ?
    """, (status, email))

    conn.commit()
    affected = cursor.rowcount
    conn.close()

    return affected > 0

# Initialize database on import
init_db()
