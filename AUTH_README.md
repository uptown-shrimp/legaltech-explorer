# Authentication System Documentation

## Overview

This application now includes a secure invite-only authentication system. Users must be invited by an admin to create an account and access the application.

## Key Security Features

✅ **Server-side credential storage** - All passwords are hashed using bcrypt
✅ **No hardcoded secrets** - Credentials never appear in frontend code
✅ **HTTP-only cookies** - Session tokens cannot be accessed by JavaScript
✅ **Invite-only registration** - Users can only register with valid invite links
✅ **Session management** - Secure session handling with expiration
✅ **Admin controls** - Only admins can create invites

## Setup Instructions

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

This will install:
- `passlib[bcrypt]` - Password hashing
- `python-multipart` - Form data parsing

### 2. Create Your First Admin User

Use the admin CLI tool to create an admin account:

```bash
python admin_cli.py create-admin admin@yourcompany.com YourSecurePassword123
```

Output:
```
✓ Admin user created successfully!
  Email: admin@yourcompany.com
  User ID: 1

  You can now login with these credentials.
```

### 3. Start the Server

```bash
uvicorn ai_search_api:app --host 0.0.0.0 --port 8000
```

## Usage

### For Admins: Creating Invite Links

#### Method 1: Using the CLI Tool (Recommended)

Create a user invite:
```bash
python admin_cli.py create-invite user@example.com
```

Create an admin invite:
```bash
python admin_cli.py create-invite admin2@example.com --role admin
```

Create an invite with client ID (for multi-tenant setups):
```bash
python admin_cli.py create-invite client@law-firm.com --client-id law-firm-123
```

Output:
```
✓ Invite created successfully!
  Email: user@example.com
  Role: user

  Token: abc123xyz789...

  Invite URL:
  https://your-domain.com/register?token=abc123xyz789...

  This invite will expire in 72 hours.
```

#### Method 2: Using the API (Programmatic)

First, login to get a session:

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourcompany.com","password":"YourSecurePassword123"}' \
  -c cookies.txt
```

Then create an invite:

```bash
curl -X POST http://localhost:8000/admin/invite \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"email":"user@example.com","role":"user"}'
```

### For Users: Registering with an Invite

1. Receive an invite link from an admin (e.g., `https://your-domain.com/register?token=abc123xyz789...`)
2. Click the link - you'll be taken to a registration page
3. The email will be pre-filled (from the invite)
4. Choose a secure password (minimum 8 characters)
5. Click "Create Account"
6. You'll be automatically logged in and redirected to the app

### For Users: Logging In

1. Visit the application homepage
2. Click the login button (or you'll be redirected if auth is required)
3. Enter your email and password
4. Click "Sign In"

### Logging Out

Click your email address in the header and select "Sign Out"

## Integration with index.html

To enable authentication on your frontend, add this line to `index.html` before the closing `</body>` tag:

```html
<!-- Authentication UI -->
<script src="auth_ui.html"></script>
```

Or manually include the auth modal HTML and JavaScript from `auth_ui.html`.

## API Endpoints

### Public Endpoints

- `POST /auth/login` - Login with email/password
- `POST /auth/register` - Register with invite token
- `GET /auth/check-invite/{token}` - Validate an invite token

### Authenticated Endpoints

- `GET /auth/me` - Get current user info
- `POST /auth/logout` - Logout (delete session)

### Admin Endpoints

- `POST /admin/invite` - Create a new invite (requires admin role)

## Optional: Requiring Authentication

By default, the app is publicly accessible. To require authentication:

1. Edit `ai_search_api.py`
2. Find the root route (`@app.get("/")`)
3. Change from:
   ```python
   async def root(user: Optional[dict] = Depends(get_current_user)):
   ```
   To:
   ```python
   async def root(user: dict = Depends(require_auth)):
   ```

4. Same for other routes you want to protect (e.g., `/query`, `/summarize`)

## Multi-Client Support (Optional)

If you want to separate data by client:

1. When creating invites, specify a `client_id`:
   ```bash
   python admin_cli.py create-invite user@client.com --client-id client-abc
   ```

2. In your data queries, filter by the user's `client_id`:
   ```python
   @app.get("/tools")
   async def get_tools(user: dict = Depends(require_auth)):
       client_id = user.get('client_id')
       # Filter tools by client_id
   ```

## Database

The authentication system uses SQLite and creates an `auth.db` file with three tables:

- `users` - User accounts (email, password_hash, role, status)
- `invites` - Invite tokens (token, email, expiry, used status)
- `sessions` - Active sessions (session_id, user_id, expiry)

### Database Location

By default: `auth.db` in the application directory

To change location, set environment variable:
```bash
export AUTH_DB_FILE=/path/to/auth.db
```

## Security Best Practices

1. **Use HTTPS in production** - Session cookies are marked `secure=True`
2. **Set strong passwords** - Minimum 8 characters (enforced in UI)
3. **Rotate invite links** - Invites expire after 72 hours by default
4. **Monitor sessions** - Sessions expire after 24 hours
5. **Keep admin credentials secret** - Store in environment variables or secrets manager
6. **Regular security audits** - Review user accounts and sessions periodically

## Troubleshooting

### "Invalid email or password"
- Check that the user account exists
- Verify the password is correct
- Ensure the user status is "active"

### "Invalid or expired invite"
- Invite may have expired (72 hours)
- Invite may have already been used
- Verify the token is correct

### "Admin access required"
- Only users with role='admin' can create invites
- Check user role in database: `SELECT * FROM users WHERE email='...'`

### Session not persisting
- Ensure cookies are enabled in browser
- Check that the app is running on HTTPS in production (for secure cookies)
- Verify session hasn't expired (24-hour default)

## Environment Variables

- `AUTH_DB_FILE` - Path to authentication database (default: `auth.db`)
- `OPENAI_API_KEY` - OpenAI API key (existing)
- `OPENAI_MODEL` - OpenAI model name (existing)

## Production Deployment

### On Render

1. Add the new dependencies to `requirements.txt` (already done)
2. The database will be created automatically on first run
3. SSH into your Render instance or use a one-off job to create the first admin:
   ```bash
   python admin_cli.py create-admin admin@yourcompany.com SecurePassword
   ```
4. Set `secure=True` for cookies (already configured)
5. Ensure your domain uses HTTPS (Render provides this automatically)

### Database Persistence

⚠️ **Important**: On Render's free tier, the filesystem is ephemeral. Your `auth.db` will be lost on restarts.

Solutions:
1. **Use Render's PostgreSQL** - Migrate from SQLite to PostgreSQL (recommended for production)
2. **Use persistent disk** - Upgrade to a paid plan with persistent storage
3. **External database** - Use a managed database service

For PostgreSQL migration, update `auth_models.py` to use SQLAlchemy with PostgreSQL instead of sqlite3.

## Next Steps

1. Create your admin account
2. Test login/logout locally
3. Create a test invite
4. Register with the invite
5. Deploy to production
6. Create production admin account
7. Invite your users!

## Support

For issues or questions about the authentication system, check:
- Application logs (`uvicorn` console output)
- Browser console (F12) for frontend errors
- `auth.db` database for user/session data
