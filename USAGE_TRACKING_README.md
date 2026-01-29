# Usage Tracking & User Management

This document explains how to track consultant usage and manage user access for the Legal-Tech Explorer.

## Overview

The system automatically tracks:
- Every query made by each user
- Tools compared by each user
- Timestamps of all activity
- Total request counts per user

Admins can:
- View all users and their usage statistics
- View detailed activity for specific users
- Disable/enable user accounts
- Monitor usage via CLI or API

## Database

All usage is stored in the `auth.db` SQLite database in the `usage_logs` table:

```sql
CREATE TABLE usage_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    user_email TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    query_text TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
```

## Viewing Usage Statistics

### Method 1: CLI Tool (Easiest)

The `usage_cli.py` script provides a simple command-line interface:

```bash
# List all users with usage statistics
python usage_cli.py list

# View detailed statistics for a specific user
python usage_cli.py stats consultant@example.com

# Disable a user account
python usage_cli.py disable consultant@example.com

# Re-enable a user account
python usage_cli.py enable consultant@example.com
```

**Example output:**

```
================================================================================
ALL USERS - USAGE STATISTICS
================================================================================

Email                               Role       Status     Requests   Last Login
--------------------------------------------------------------------------------
admin@test.com                      admin      active     5          2025-01-29 14:30
consultant1@example.com             user       active     45         2025-01-29 15:22
consultant2@example.com             user       active     23         2025-01-28 10:15
consultant3@example.com             user       disabled   12         2025-01-27 16:45
```

### Method 2: Admin API Endpoints

If you're building a web dashboard or want programmatic access:

#### List all users with usage statistics
```bash
GET /admin/users
Authorization: (must be logged in as admin)

Response:
{
  "users": [
    {
      "id": 1,
      "email": "consultant@example.com",
      "role": "user",
      "status": "active",
      "created_at": "2025-01-20T10:30:00",
      "last_login": "2025-01-29T15:22:00",
      "total_requests": 45
    },
    ...
  ]
}
```

#### View detailed stats for a specific user
```bash
GET /admin/users/{email}/stats
Authorization: (must be logged in as admin)

Response:
{
  "email": "consultant@example.com",
  "total_requests": 45,
  "by_endpoint": [
    {"endpoint": "/query", "count": 38},
    {"endpoint": "/summarize", "count": 7}
  ],
  "recent_activity": [
    {
      "endpoint": "/query",
      "query_text": "contract management tools for Australian firms",
      "created_at": "2025-01-29T15:22:00"
    },
    ...
  ]
}
```

#### Disable or enable a user account
```bash
POST /admin/users/{email}/status
Authorization: (must be logged in as admin)
Content-Type: application/json

{
  "status": "disabled"  // or "active" to re-enable
}

Response:
{
  "success": true,
  "email": "consultant@example.com",
  "status": "disabled"
}
```

## Revoking Access

To revoke a consultant's access:

```bash
# Using the CLI
python usage_cli.py disable consultant@example.com

# Using the API
curl -X POST http://localhost:8000/admin/users/consultant@example.com/status \
  -H "Content-Type: application/json" \
  -d '{"status": "disabled"}' \
  --cookie "session_id=YOUR_ADMIN_SESSION"
```

When a user is disabled:
- They cannot login (existing sessions are invalidated)
- They cannot access any protected endpoints
- Their historical data remains in the database

To re-enable them later:

```bash
python usage_cli.py enable consultant@example.com
```

## Workflow for Consultant Groups

### 1. Initial Setup

Create invites for each consultant:

```bash
python admin_cli.py create-invite consultant1@clario.com.au
python admin_cli.py create-invite consultant2@clario.com.au
python admin_cli.py create-invite consultant3@clario.com.au
```

Send each consultant their unique invite link.

### 2. During Active Use

Monitor usage regularly:

```bash
# Quick overview
python usage_cli.py list

# Detailed analysis for heavy users
python usage_cli.py stats consultant1@clario.com.au
```

### 3. Project Completion

Revoke access for all consultants:

```bash
python usage_cli.py disable consultant1@clario.com.au
python usage_cli.py disable consultant2@clario.com.au
python usage_cli.py disable consultant3@clario.com.au
```

### 4. Reporting

Generate a usage report by querying the database directly:

```bash
sqlite3 auth.db

-- Total queries per user
SELECT user_email, COUNT(*) as total_queries
FROM usage_logs
GROUP BY user_email
ORDER BY total_queries DESC;

-- Activity over time
SELECT DATE(created_at) as date, user_email, COUNT(*) as queries
FROM usage_logs
GROUP BY date, user_email
ORDER BY date DESC;

-- Most common search terms
SELECT query_text, COUNT(*) as count
FROM usage_logs
WHERE endpoint = '/query'
GROUP BY query_text
ORDER BY count DESC
LIMIT 20;
```

## Testing

Run the comprehensive test suite:

```bash
python test_usage_tracking.py
```

This will:
1. Login as admin and regular user
2. Make test queries
3. View usage statistics
4. Disable/enable accounts
5. Verify access control

## Deployment to Render

When deploying to Render, the usage tracking works automatically:

1. All usage is stored in the `auth.db` SQLite database on the server
2. The database persists between deployments (stored in `/opt/render/project/src`)
3. Access the CLI tools via SSH to the Render instance:

```bash
# SSH to your Render instance
render ssh

# Run CLI commands
python usage_cli.py list
python usage_cli.py stats consultant@example.com
python usage_cli.py disable consultant@example.com
```

Alternatively, use the admin API endpoints from any HTTP client.

## Security Notes

- All admin endpoints require authentication with an admin role
- Regular users cannot access usage statistics (403 Forbidden)
- Disabled users cannot login or access any protected endpoints
- Session cookies are HTTP-only (XSS protection)
- Passwords are hashed with bcrypt

## Rate Limiting Integration

Usage tracking works alongside rate limiting:
- Rate limit: 20 requests per 60 seconds per user
- Rate limited requests are NOT logged to usage_logs
- Only successful requests are tracked

## Questions?

For the deployed version on Render:
1. Admin login: Use your admin credentials
2. View usage: Use the CLI via SSH or the admin API endpoints
3. Revoke access: `python usage_cli.py disable <email>`
4. Export data: Query the SQLite database directly

All data is stored in `auth.db` on the server.
