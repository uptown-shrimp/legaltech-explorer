# ai_search_api.py
import os
import json
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Cookie, Request, Response, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import OpenAI

# Import Supabase authentication
from supabase_auth import (
    sign_in, sign_out, sign_up, get_user_from_token, refresh_session,
    request_password_reset, update_password, admin_create_user, admin_invite_user,
    admin_list_users, is_configured as supabase_configured
)

# Import usage tracking (still using PostgreSQL)
from auth_models import log_usage, get_user_stats, get_all_users_stats

# =========================
# Boot + OpenAI client
# =========================
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
# Default to a widely available model. Override via .env OPENAI_MODEL=...
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
client = OpenAI(api_key=OPENAI_API_KEY)

app = FastAPI(title="Legal-Tech Filter API", version="0.2.0")

# CORS (dev-friendly)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://0.0.0.0:5500",
        "*",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for logos
app.mount("/logos", StaticFiles(directory="logos"), name="logos")

# =========================
# Rate Limiting
# =========================
# Store request timestamps per user: {user_email: [timestamp1, timestamp2, ...]}
rate_limit_store: Dict[str, List[float]] = defaultdict(list)

# Rate limit configuration
RATE_LIMIT_REQUESTS = 20  # Number of requests allowed
RATE_LIMIT_WINDOW = 60    # Time window in seconds (1 minute)

def check_rate_limit(user_email: str) -> bool:
    """
    Check if user has exceeded rate limit.
    Returns True if within limit, False if exceeded.
    """
    now = time.time()

    # Clean up old timestamps outside the window
    rate_limit_store[user_email] = [
        ts for ts in rate_limit_store[user_email]
        if now - ts < RATE_LIMIT_WINDOW
    ]

    # Check if user has exceeded the limit
    if len(rate_limit_store[user_email]) >= RATE_LIMIT_REQUESTS:
        return False

    # Add current timestamp
    rate_limit_store[user_email].append(now)
    return True

# =========================
# Schema your UI understands
# =========================
SCHEMA_FIELDS: List[str] = [
    "Vendor Name", "Vendor Overview", "HQ", "Office Locations", "Regions Served",
    "Year Founded", "Product Name", "Product Description", "Languages Supported",
    "Legal Functionality", "Functionality Sub-Category",
    "Main problem solved", "Primary User Segment", "Maturity Entry Level",
    "Industry Focus", "AI Powered", "AI Platform Type", "Deployment Model",
    "Hosting Location", "Hosting Provider", "ISO Certifications",
    "Security & Compliance Certifications", "Pricing Model",
    "Approx. Price Range (AUD)", "Demo / Proof of Concept Available",
    "Adoption Level", "Ease of Purchase", "Customer Reviews",
    "Customer Feedback Rating", "Vendor Contact Details", "Vendor Website"
]

MULTI_FIELDS = {
    # Note: These are stored as multi-value in CSV but rendered as single dropdowns in UI
    "Regions Served", "Primary User Segment", "AI Platform Type",
    "ISO Certifications", "Security & Compliance Certifications"
}

# =========================
# Canonicalisation maps
# =========================
MAIN_CATEGORY_CANON = {
    "contract automation": "Contracting & Document Automation",
    "contract review": "Contracting & Document Automation",
    "contract": "Contracting & Document Automation",
    "document automation": "Contracting & Document Automation",
    "document": "Contracting & Document Automation",
    "esignature": "Contracting & Document Automation",
    "e-signature": "Contracting & Document Automation",
    "matter management": "Matter, Workflow & Intake Management",
    "matter": "Matter, Workflow & Intake Management",
    "workflow": "Matter, Workflow & Intake Management",
    "intake": "Matter, Workflow & Intake Management",
    "operations": "Legal Operations & Analytics",
    "analytics": "Legal Operations & Analytics",
    "ops": "Legal Operations & Analytics",
    "spend management": "Legal Operations & Analytics",
    "vendor management": "Legal Operations & Analytics",
    "ebilling": "Legal Operations & Analytics",
    "e-billing": "Legal Operations & Analytics",
    "outside counsel": "Outside Counsel & Spend Management",
    "compliance": "Compliance, Risk & Governance",
    "risk": "Compliance, Risk & Governance",
    "governance": "Corporate Governance & Entity Management",
    "entity management": "Corporate Governance & Entity Management",
    "litigation": "Litigation, Disputes & Investigations",
    "ediscovery": "Litigation, Disputes & Investigations",
    "e-discovery": "Litigation, Disputes & Investigations",
    "dispute": "Litigation, Disputes & Investigations",
    "ip": "Intellectual Property, Technology & Data",
    "intellectual property": "Intellectual Property, Technology & Data",
    "patent": "Intellectual Property, Technology & Data",
    "patents": "Intellectual Property, Technology & Data",
    "ip portfolio": "Intellectual Property, Technology & Data",
    "trademark": "Intellectual Property, Technology & Data",
    "copyright": "Intellectual Property, Technology & Data",
    "technology": "Intellectual Property, Technology & Data",
    "employment": "Employment & HR Legal Support",
    "hr": "Employment & HR Legal Support",
    "cross-border": "Cross-Border, Transactions & Deal Management",
    "transactions": "Cross-Border, Transactions & Deal Management",
    "deal management": "Cross-Border, Transactions & Deal Management",
    "m&a": "Cross-Border, Transactions & Deal Management",
    "mergers and acquisitions": "Cross-Border, Transactions & Deal Management",
    "deal": "Cross-Border, Transactions & Deal Management",
    "knowledge management": "Knowledge, Search & Precedent Management",
    "knowledge": "Knowledge, Search & Precedent Management",
    "search": "Knowledge, Search & Precedent Management",
    "precedent": "Knowledge, Search & Precedent Management",
    "document management": "Knowledge, Search & Precedent Management",
    "ai assistant": "AI Legal Assistants & Productivity Tools",
    "assistant": "AI Legal Assistants & Productivity Tools",
    "productivity": "AI Legal Assistants & Productivity Tools",
    "integration": "Integration & Platform Infrastructure",
    "legal research": "Legal Research & Knowledge",
    "research": "Legal Research & Knowledge",
}

USER_SEGMENT_CANON = {
    "in-house": "Corporate legal",
    "inhouse": "Corporate legal",
    "corporate": "Corporate legal",
    "private practice": "Private practice",
    "law firm": "Private practice",
    "alsp": "Alternative Legal Service Providers (ALSPs)",
    "legal ops": "Legal Operations Professionals",
    "ops": "Legal Operations Professionals",
    "procurement": "Contract Management Teams / Procurement",
    "compliance": "Compliance & Risk Teams",
    "risk": "Compliance & Risk Teams",
    "litigation": "Litigation / Disputes Teams",
    "dispute": "Litigation / Disputes Teams",
    "ip": "Intellectual Property Teams.",
}

class Query(BaseModel):
    query: str

class ComparisonRequest(BaseModel):
    tools: List[Dict[str, Any]]

# =========================
# Authentication Models
# =========================
class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    token: str
    password: str

class SignUpRequest(BaseModel):
    email: str
    password: str

class InviteRequest(BaseModel):
    email: str
    role: str = "user"
    client_id: Optional[str] = None

# =========================
# Authentication Dependency (Supabase)
# =========================
async def get_current_user(
    access_token: Optional[str] = Cookie(None, alias="sb_access_token"),
    authorization: Optional[str] = Header(None)
):
    """Dependency to get current authenticated user from Supabase JWT"""
    # Try to get token from Authorization header first, then cookie
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    elif access_token:
        token = access_token

    if not token:
        return None

    user = get_user_from_token(token)
    return user

async def require_auth(user: Optional[dict] = Depends(get_current_user)):
    """Dependency that requires authentication"""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

async def require_admin(user: dict = Depends(require_auth)):
    """Dependency that requires admin role"""
    if user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

async def rate_limit_dependency(user: dict = Depends(require_auth)):
    """Dependency to enforce rate limiting on authenticated endpoints"""
    if not check_rate_limit(user['email']):
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Maximum {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds."
        )
    return user

# =========================
# Helpers
# =========================
def coerce_value(key: str, val: Any):
    if key in MULTI_FIELDS:
        if val is None or val == "":
            return []
        if isinstance(val, list):
            return [str(x).strip() for x in val if str(x).strip()]
        return [x.strip() for x in str(val).split(",") if x.strip()]
    else:
        if val is None:
            return ""
        if isinstance(val, (list, dict)):
            if isinstance(val, list):
                return ", ".join(str(x) for x in val)
            return json.dumps(val)
        return str(val)

def canonicalize_main_category(val: str) -> str:
    s = (val or "").lower().strip()

    # If already a valid category, return as-is
    if val in MAIN_CATEGORY_CANON.values():
        return val

    # Try exact matches first (more specific)
    for k, target in MAIN_CATEGORY_CANON.items():
        if s == k:
            return target

    # Then try substring matches (less specific, might catch more)
    # Prioritize longer matches to avoid false positives
    matches = []
    for k, target in MAIN_CATEGORY_CANON.items():
        if k in s:
            matches.append((len(k), target))

    if matches:
        # Return the longest matching key's target
        matches.sort(reverse=True)
        return matches[0][1]

    return val

def canonicalize_user_segments(vals):
    if isinstance(vals, str):
        vals = [vals]
    out = []
    for v in (vals or []):
        if v in USER_SEGMENT_CANON.values():
            out.append(v); continue
        s = (v or "").lower()
        mapped = None
        for k, target in USER_SEGMENT_CANON.items():
            if k in s:
                mapped = target
                break
        out.append(mapped or v)
    seen, clean = set(), []
    for v in out:
        if v not in seen:
            seen.add(v); clean.append(v)
    return clean

def normalize_to_schema(model_obj: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    synonyms = {
        "location": "Regions Served",
        "locations": "Regions Served",
        "region": "Regions Served",
        "regions": "Regions Served",
        "target_audience": "Primary User Segment",
        "audience": "Primary User Segment",
        "users": "Primary User Segment",
        "use_case": "Legal Functionality",
        "Legal Functionality – Main Category": "Legal Functionality",
        "Legal Functionality – Sub-Category": "Functionality Sub-Category",
        "AI Maturity Stage": "Maturity Entry Level",
        "AI Platform": "AI Platform Type",
        "Hosting Location / Data Residence": "Hosting Location",
        "Languages supported": "Languages Supported",
        "Main Problem Solved": "Main problem solved",
    }

    # Value normalization maps
    value_normalizations = {
        "AI Powered": {
            "True": "Yes",
            "true": "Yes",
            "False": "No",
            "false": "No",
        },
        "Maturity Entry Level": {
            "Enterprise": "Enterprise-grade",
            "Quick win": "Quick Win",
            "quick win": "Quick Win",
        },
        "Primary User Segment": {
            "Government agencies": "Government / Public Sector",
            "Government": "Government / Public Sector",
            "Govt": "Government / Public Sector",
        },
    }

    for k, v in model_obj.items():
        if k in SCHEMA_FIELDS:
            out[k] = coerce_value(k, v)

    for k, v in model_obj.items():
        lk = str(k).strip()
        if lk in synonyms:
            target = synonyms[lk]
            if target in SCHEMA_FIELDS and target not in out:
                out[target] = coerce_value(target, v)

    if "Regions Served" in out and isinstance(out["Regions Served"], str):
        out["Regions Served"] = [out["Regions Served"]]

    if "Legal Functionality" in out:
        out["Legal Functionality"] = canonicalize_main_category(
            out["Legal Functionality"]
        )
    if "Primary User Segment" in out:
        out["Primary User Segment"] = canonicalize_user_segments(out["Primary User Segment"])

    # Apply value normalizations
    for field, norm_map in value_normalizations.items():
        if field in out:
            val = out[field]
            if isinstance(val, str) and val in norm_map:
                out[field] = norm_map[val]
            elif isinstance(val, list):
                out[field] = [norm_map.get(v, v) for v in val]

    out = {k: v for k, v in out.items() if v not in ("", [], None)}
    return out

FALLBACK_MODELS = [
    OPENAI_MODEL,
    "gpt-4.1-mini",
    "o4-mini",
    "gpt-4o-mini",
]

def call_openai_json(system_msg: str, user_msg: str) -> Dict[str, Any]:
    last_err = None
    for m in FALLBACK_MODELS:
        try:
            resp = client.chat.completions.create(
                model=m,
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.2,
                response_format={"type": "json_object"},
            )
            raw = resp.choices[0].message.content
            return json.loads(raw) if isinstance(raw, str) else raw
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            continue
    raise RuntimeError(f"All model attempts failed. Last error: {last_err}")

# =========================
# Routes
# =========================

# =========================
# Authentication Routes (Supabase)
# =========================

# Helper function for cookie settings
def get_cookie_secure():
    """Return True if running in production (HTTPS), False for development (HTTP)"""
    return os.getenv("ENVIRONMENT", "development") == "production"

@app.post("/auth/login")
async def login(req: LoginRequest, response: Response):
    """Login endpoint - authenticates user via Supabase"""
    result = sign_in(req.email, req.password)

    if "error" in result:
        raise HTTPException(status_code=401, detail=result["error"])

    user = result["user"]
    session = result["session"]

    # Set access token as HTTP-only cookie
    response.set_cookie(
        key="sb_access_token",
        value=session["access_token"],
        httponly=True,
        secure=get_cookie_secure(),
        samesite="lax",
        max_age=3600  # 1 hour (Supabase default)
    )

    # Set refresh token as HTTP-only cookie
    response.set_cookie(
        key="sb_refresh_token",
        value=session["refresh_token"],
        httponly=True,
        secure=get_cookie_secure(),
        samesite="lax",
        max_age=86400 * 7  # 7 days
    )

    return {
        "success": True,
        "user": {
            "email": user["email"],
            "role": user.get("role", "user")
        },
        "access_token": session["access_token"]  # Also return for frontend storage
    }

@app.post("/auth/logout")
async def logout(
    response: Response,
    access_token: Optional[str] = Cookie(None, alias="sb_access_token")
):
    """Logout endpoint - clears session cookies"""
    if access_token:
        sign_out(access_token)

    response.delete_cookie(key="sb_access_token")
    response.delete_cookie(key="sb_refresh_token")

    return {"success": True}

@app.get("/auth/me")
async def get_me(user: Optional[dict] = Depends(get_current_user)):
    """Get current user info"""
    if not user:
        return {"authenticated": False}

    return {
        "authenticated": True,
        "user": {
            "email": user["email"],
            "role": user.get("role", "user"),
            "id": user.get("id")
        }
    }

@app.post("/auth/refresh")
async def refresh_token_endpoint(
    response: Response,
    refresh_token: Optional[str] = Cookie(None, alias="sb_refresh_token")
):
    """Refresh access token using refresh token"""
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    result = refresh_session(refresh_token)

    if "error" in result:
        # Clear invalid cookies
        response.delete_cookie(key="sb_access_token")
        response.delete_cookie(key="sb_refresh_token")
        raise HTTPException(status_code=401, detail=result["error"])

    session = result["session"]

    # Update cookies with new tokens
    response.set_cookie(
        key="sb_access_token",
        value=session["access_token"],
        httponly=True,
        secure=get_cookie_secure(),
        samesite="lax",
        max_age=3600
    )

    response.set_cookie(
        key="sb_refresh_token",
        value=session["refresh_token"],
        httponly=True,
        secure=get_cookie_secure(),
        samesite="lax",
        max_age=86400 * 7
    )

    return {
        "success": True,
        "access_token": session["access_token"]
    }

@app.post("/auth/forgot-password")
async def forgot_password(req: LoginRequest):
    """Request password reset email"""
    # Get the site URL for redirect - redirect to main page, frontend handles token
    site_url = os.getenv("SITE_URL", "https://legaltech-explorer.onrender.com")
    redirect_url = site_url  # Redirect to main page, not /reset-password

    result = request_password_reset(req.email, redirect_url)

    # Always return success to prevent email enumeration
    return {"success": True, "message": "If an account exists, a reset email has been sent"}

@app.post("/auth/signup")
async def signup(req: SignUpRequest):
    """Public sign-up — Supabase sends a verification email automatically"""
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    result = sign_up(req.email, req.password)

    if "error" in result:
        error = result["error"]
        if "already registered" in error.lower() or "already exists" in error.lower():
            raise HTTPException(status_code=409, detail="An account with this email already exists")
        raise HTTPException(status_code=400, detail=error)

    return {
        "success": True,
        "message": "Account created. Please check your email to verify your account before signing in."
    }

class UpdatePasswordRequest(BaseModel):
    password: str

@app.post("/auth/update-password")
async def update_password_endpoint(
    req: UpdatePasswordRequest,
    access_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None)
):
    """Update user's password (requires valid recovery session)"""
    # Get token from cookie or header
    token = access_token
    if not token and authorization:
        if authorization.startswith("Bearer "):
            token = authorization[7:]

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    result = update_password(token, req.password)

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return {"success": True, "message": "Password updated successfully"}

# =========================
# Admin Routes (User Management via Supabase)
# =========================
@app.post("/admin/invite")
async def create_invite_endpoint(req: InviteRequest, admin: dict = Depends(require_admin)):
    """Admin endpoint to send invite email via Supabase"""
    site_url = os.getenv("SITE_URL", "https://legaltech-explorer.onrender.com")

    result = admin_invite_user(
        email=req.email,
        role=req.role,
        redirect_url=site_url
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return {
        "success": True,
        "email": req.email,
        "message": "Invite email sent"
    }

@app.post("/admin/create-user")
async def create_user_endpoint(req: LoginRequest, admin: dict = Depends(require_admin)):
    """Admin endpoint to create user directly with password"""
    result = admin_create_user(
        email=req.email,
        password=req.password,
        role="user"
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return {
        "success": True,
        "user": result["user"]
    }

@app.get("/admin/users")
async def list_users_endpoint(admin: dict = Depends(require_admin)):
    """Admin endpoint to list all users"""
    result = admin_list_users()

    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])

    return result

@app.get("/admin/users")
async def list_users_endpoint(admin: dict = Depends(require_admin)):
    """Admin endpoint to list all users with usage statistics"""
    users = get_all_users_stats()
    return {"users": users}

@app.get("/admin/users/{email}/stats")
async def get_user_stats_endpoint(email: str, admin: dict = Depends(require_admin)):
    """Admin endpoint to get detailed statistics for a specific user"""
    stats = get_user_stats(email)
    return stats

class UserStatusRequest(BaseModel):
    status: str  # 'active' or 'disabled'

@app.post("/admin/users/{email}/status")
async def set_user_status_endpoint(email: str, req: UserStatusRequest, admin: dict = Depends(require_admin)):
    """Admin endpoint to enable or disable a user account"""
    if req.status not in ['active', 'disabled']:
        raise HTTPException(status_code=400, detail="Status must be 'active' or 'disabled'")

    success = set_user_status(email, req.status)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "success": True,
        "email": email,
        "status": req.status
    }

# =========================
# Public Routes
# =========================
@app.get("/")
async def root(user: Optional[dict] = Depends(get_current_user)):
    """Serve index.html - with optional authentication"""
    response = FileResponse("index.html")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.get("/login.html")
async def login_page():
    """Serve login page"""
    response = FileResponse("login.html")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.get("/merged_pref_top50.csv")
def serve_csv(user: dict = Depends(require_auth)):
    return FileResponse("merged_pref_top50.csv", media_type="text/csv")

@app.get("/merged_pref_top50_updated.csv")
def serve_updated_csv(user: dict = Depends(require_auth)):
    response = FileResponse("merged_pref_top50_updated.csv", media_type="text/csv")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.get("/health")
def health():
    return {"ok": True, "has_key": bool(OPENAI_API_KEY), "model": OPENAI_MODEL}

@app.post("/query")
async def generate_filters(req: Query, user: dict = Depends(rate_limit_dependency)):
    system_msg = (
        "You map natural-language legal-tech needs into structured filters for a database.\n"
        "Return ONLY a single JSON object (no markdown, no prose) using these EXACT field names when applicable:\n"
        f"{SCHEMA_FIELDS}\n\n"
        "Guidelines:\n"
        "- IMPORTANT: Do NOT set 'Regions Served' filter unless the user explicitly wants to filter BY region.\n"
        "  If the query mentions 'in Australia' or 'for Australian teams', this is just context, NOT a filter requirement.\n"
        "  Only set 'Regions Served' if the user says something like 'only Australian vendors' or 'must be based in Australia'.\n"
        "- For 'Legal Functionality', use ONE of these exact values:\n"
        "  * 'Contracting & Document Automation' (for contract automation, document automation, esignature, contract review)\n"
        "  * 'Matter, Workflow & Intake Management' (for matter management, workflow automation, intake)\n"
        "  * 'Legal Operations & Analytics' (for legal ops, analytics, reporting, ebilling)\n"
        "  * 'Outside Counsel & Spend Management' (ONLY for tools primarily focused on outside counsel management)\n"
        "  * 'Litigation, Disputes & Investigations' (for litigation, ediscovery, disputes)\n"
        "  * 'Knowledge, Search & Precedent Management' (for document management, knowledge management)\n"
        "  * 'Legal Research & Knowledge' (for legal research)\n"
        "  * 'AI Legal Assistants & Productivity Tools' (for AI assistants, copilots)\n"
        "  * 'Compliance, Risk & Governance' (for compliance, risk management)\n"
        "  * 'Intellectual Property, Technology & Data' (for patents, trademarks, IP portfolio, copyright)\n"
        "  * Other categories as applicable\n"
        "- For 'Primary User Segment', use ONE of: 'Corporate legal', 'Private practice', 'Legal Operations Professionals', etc.\n"
        "- IMPORTANT: For broad searches like 'spend management' or 'vendor management', use 'Legal Operations & Analytics' as the category\n"
        "  since most spend tools are in that category, NOT 'Outside Counsel & Spend Management'.\n"
        "- For 'AI Powered', use EXACTLY: 'Yes' or 'No' (NOT True/False)\n"
        "- For 'Deployment Model', use EXACTLY: 'Cloud (SaaS)' NOT 'Cloud-based'\n"
        "- For 'Maturity Entry Level', use ONE of: 'Enterprise-grade', 'Advanced', 'Quick Win', 'Experimental / early stage'\n"
        "- For 'Approx. Price Range (AUD)', use EXACTLY: '<$10K', '$10K–$50K', '$51K-$100K', or '$101K+'\n"
        "- For 'Ease of Purchase', use ONE of: 'Very Easy', 'Easy', 'Moderate', 'Complex'\n"
        "- For 'Primary User Segment' with government, use 'Government / Public Sector' NOT 'Government agencies'\n"
        "- Do NOT include 'Functionality Sub-Category' - focus on main category only.\n"
        "- Never invent vendor names or prices. Only filters.\n"
        "- If unsure about a field, omit it entirely.\n"
        "- Output JSON only, no explanations."
    )

    user_msg = f"User query:\n{req.query}\n\nReturn only the JSON object with filters."

    try:
        # Log the query
        log_usage(user['id'], user['email'], '/query', req.query)

        model_obj = call_openai_json(system_msg, user_msg)
        clean = normalize_to_schema(model_obj)
        return clean
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/summarize")
async def summarize_comparison(req: ComparisonRequest, user: dict = Depends(rate_limit_dependency)):
    """
    Generate an AI summary comparing multiple legal tech tools.
    """
    if not req.tools or len(req.tools) == 0:
        return JSONResponse(status_code=400, content={"error": "No tools provided for comparison"})

    # Build a comparison prompt
    tools_text = ""
    for i, tool in enumerate(req.tools, 1):
        tools_text += f"\n\n**Tool {i}: {tool.get('name', 'Unknown')}**\n"
        tools_text += f"- Vendor: {tool.get('vendor', 'N/A')}\n"
        tools_text += f"- Description: {tool.get('description', 'N/A')}\n"
        tools_text += f"- Pricing: {tool.get('pricing', 'N/A')}\n"
        tools_text += f"- Deployment: {tool.get('deployment', 'N/A')}\n"
        tools_text += f"- AI Powered: {tool.get('aiPowered', 'N/A')}\n"
        tools_text += f"- Ease of Purchase: {tool.get('easeOfPurchase', 'N/A')}\n"
        tools_text += f"- Adoption Level: {tool.get('adoptionLevel', 'N/A')}\n"

    system_msg = (
        "You are an expert legal technology consultant. Analyze the provided legal tech tools and generate "
        "a concise, insightful comparison summary. Focus on:\n"
        "1. Key similarities and differences\n"
        "2. Strengths and weaknesses of each tool\n"
        "3. Best use cases for each tool\n"
        "4. Pricing and value considerations\n"
        "5. A recommendation based on common use cases\n\n"
        "Format your response in clean HTML with paragraphs and bullet points. "
        "Keep it under 300 words and make it actionable for legal teams making purchasing decisions.\n"
        "Return ONLY a JSON object with a single 'summary' field containing the HTML content."
    )

    user_msg = f"Compare these legal tech tools:{tools_text}\n\nProvide a comparison summary in JSON format."

    try:
        # Log the comparison request
        tool_names = [t.get('name', 'Unknown') for t in req.tools]
        log_usage(user['id'], user['email'], '/summarize', f"Comparing: {', '.join(tool_names)}")

        result = call_openai_json(system_msg, user_msg)
        if isinstance(result, dict) and 'summary' in result:
            return {"summary": result['summary']}
        else:
            # Fallback if the response doesn't have expected format
            return {"summary": str(result)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
