# ai_search_api.py
import os
import json
from typing import Any, Dict, List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import OpenAI

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

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# =========================
# Schema your UI understands
# =========================
SCHEMA_FIELDS: List[str] = [
    "Vendor Name", "Vendor Overview", "HQ", "Office Locations", "Regions Served",
    "Year Founded", "Product Name", "Product Description", "Languages supported",
    "Legal Functionality – Main Category", "Legal Functionality – Sub-Category",
    "Main Problem Solved", "Primary User Segment", "AI Maturity Stage",
    "Industry Focus", "AI Powered", "AI Platform", "Deployment Model",
    "Hosting Location / Data Residence", "Hosting Provider", "ISO Certifications",
    "Security & Compliance Certifications", "Pricing Model",
    "Approx. Price Range (AUD)", "Demo / Proof of Concept Available",
    "Adoption Level", "Ease of Purchase", "Customer Reviews",
    "Customer Feedback Rating", "Vendor Contact Details", "Vendor Website"
]

MULTI_FIELDS = {
    "Regions Served", "Primary User Segment", "AI Platform",
    "ISO Certifications", "Security & Compliance Certifications"
}

# =========================
# Canonicalisation maps
# =========================
MAIN_CATEGORY_CANON = {
    "contract automation": "Contracting & Document Automation",
    "contract": "Contracting & Document Automation",
    "document": "Contracting & Document Automation",
    "matter": "Matter, Workflow & Intake Management",
    "workflow": "Matter, Workflow & Intake Management",
    "operations": "Legal Operations & Analytics",
    "ops": "Legal Operations & Analytics",
    "spend": "Outside Counsel & Spend Management",
    "compliance": "Compliance, Risk & Governance",
    "governance": "Corporate Governance & Entity Management",
    "litigation": "Litigation, Disputes & Investigations",
    "dispute": "Litigation, Disputes & Investigations",
    "ip": "Intellectual Property, Technology & Data",
    "technology": "Intellectual Property, Technology & Data",
    "employment": "Employment & HR Legal Support",
    "hr": "Employment & HR Legal Support",
    "cross-border": "Cross-Border, Transactions & Deal Management",
    "knowledge": "Knowledge, Search & Precedent Management",
    "search": "Knowledge, Search & Precedent Management",
    "assistant": "AI Legal Assistants & Productivity Tools",
    "ai assistant": "AI Legal Assistants & Productivity Tools",
    "integration": "Integration & Platform Infrastructure",
    "research": "Legal Research & Insights.",
    "legal research": "Legal Research & Insights.",
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
    s = (val or "").lower()
    if val in MAIN_CATEGORY_CANON.values():
        return val
    for k, target in MAIN_CATEGORY_CANON.items():
        if k in s:
            return target
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
        "use_case": "Legal Functionality – Main Category",
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

    if "Legal Functionality – Main Category" in out:
        out["Legal Functionality – Main Category"] = canonicalize_main_category(
            out["Legal Functionality – Main Category"]
        )
    if "Primary User Segment" in out:
        out["Primary User Segment"] = canonicalize_user_segments(out["Primary User Segment"])

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
@app.get("/")
def root():
    return FileResponse("static/index.html")

@app.get("/health")
def health():
    return {"ok": True, "has_key": bool(OPENAI_API_KEY), "model": OPENAI_MODEL}

@app.post("/query")
async def generate_filters(req: Query):
    system_msg = (
        "You map natural-language legal-tech needs into structured filters for a database.\n"
        "Return ONLY a single JSON object (no markdown, no prose) using these EXACT field names when applicable:\n"
        f"{SCHEMA_FIELDS}\n\n"
        "Guidelines:\n"
        "- If a country/region is implied (e.g., 'in Australia'), set 'Regions Served' accordingly.\n"
        "- If a main use case is clear (e.g., 'contract automation'), set 'Legal Functionality – Main Category'.\n"
        "- Prefer enums implied by the query; if unsure, omit the field entirely.\n"
        "- Never invent vendor names or prices. Only filters.\n"
        "- Output json only."
    )

    user_msg = f"User query:\n{req.query}\n\nReturn only the JSON object."

    try:
        model_obj = call_openai_json(system_msg, user_msg)
        clean = normalize_to_schema(model_obj)
        return clean
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
