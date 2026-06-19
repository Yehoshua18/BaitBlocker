import json
import os
from typing import Optional, List
from contextlib import asynccontextmanager
from dotenv import load_dotenv

import uvicorn
from fastapi import FastAPI, HTTPException, APIRouter, Query, Response, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from fastapi_cache import FastAPICache
from fastapi_cache.backends.inmemory import InMemoryBackend

# Import your custom engine logic modules
from lexochecker import assess_url_risk
from interfaces import (check_google_safe_browsing, check_virustotal, run_url_sandbox)
from emailchecker import TextPhishingAssessment, check_email

# Load environment keys
load_dotenv()

# --- LIFECYCLE MANAGEMENT (CACHE INITIALIZATION) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize the caching system globally with an In-Memory Backend on startup
    FastAPICache.init(InMemoryBackend(), prefix="baitblocker-cache")
    yield

def post_key_builder(func, namespace: str, request: Request = None, *args, **kwargs):
    """
    Custom key builder that prevents parameter conflicts on POST endpoints
    by mapping the cache key directly to the endpoint namespace.
    """
    return f"{namespace}:{func.__name__}"

# --- INITIALIZE THE MAIN APP ---
app = FastAPI(
    lifespan=lifespan,
    title="BaitBlocker Analysis Engine",
    description="Lexicographical & External Threat Intelligence Engine",
    version="1.0.0",
    swagger_ui_parameters={
        "defaultModelsExpandDepth": -1,  # Hides the schemas section at the bottom
        "deepLinking": True,
        "displayRequestDuration": True,  # Shows application latency metrics
        "docExpansion": "list"
    }
)

# Fetch Environment Keys
GOOGLE_KEY = os.getenv("GOOGLE_API_KEY")
VT_KEY = os.getenv("VT_API_KEY")

# Endpoint to check that the keys loaded successfully
@app.get("/test-keys", include_in_schema=False)
async def test_keys():
    return {"google_loaded": bool(GOOGLE_KEY), "vt_loaded": bool(VT_KEY)}

# --- REQUEST / RESPONSE SCHEMAS ---
class AnalysisRequest(BaseModel):
    url: Optional[str] = Field(None, examples=["https://signin-netflix.xyz"])
    email_text: Optional[str] = Field(None, examples=["Urgent: update your invoice billing info."])
    run_sandbox: bool = Field(False, description="Toggle to execute heavy headless browser screenshots.")

class UrlLexicalAnalysis(BaseModel):
    url: str
    verdict: str
    risk_score: float
    reasons: List[str]

class LocalReport(BaseModel):
    url_lexical_analysis: Optional[UrlLexicalAnalysis] = None
    email_text_analysis: Optional[TextPhishingAssessment] = None

class ExternalReport(BaseModel):
    status: str
    input_received: str
    google_safe_browsing: Optional[str] = None
    risk_level_from_virus_total: Optional[str] = None
    engines_flagged_on_vt: Optional[int] = None

class SandboxReport(BaseModel):
    sandbox_status: str
    final_destination: str
    screenshot_data: Optional[str]

class AnalysisResponse(BaseModel):
    local_report: LocalReport
    external_report: ExternalReport
    sandbox: SandboxReport

# --- CORE ROUTING LOOPS ---

@app.get("/", include_in_schema=False)
async def redirect_to_docs():
    return RedirectResponse(url="/docs")

# --- INITIALIZE AND MOUNT SECURITY ROUTER ---
security_router = APIRouter(prefix="/v1/security", tags=["Security Scan"])


@security_router.get("/scan")
async def scan_url(
        response: Response,
        url: str = Query(..., description="The target URL to evaluate")
):
    """
    Evaluates a specific URL string for potential lexical anomalies.
    """
    # NOTE: This line ONLY runs on a Cache MISS.
    # If it's a Cache HIT, fastapi-cache bypasses this entire function body!
    response.headers["X-Cache"] = "MISS"

    result = await assess_url_risk(url)
    return result

#Register the router configuration blocks straight to the main app loop
app.include_router(security_router)

# --- BULK / COMPREHENSIVE ANALYSIS ENDPOINT ---
@app.post(
    "/analyze",
    response_model=AnalysisResponse,
    status_code=200,
    tags=["Core Analysis"]
)

async def analyze_input(phish: AnalysisRequest, response: Response):
    """
    Comprehensive multi-engine threat analyzer with an engineered manual cache layer.
    """

    if not phish.url and not phish.email_text:
        raise HTTPException(status_code=400, detail="Must provide a URL or email text.")

    url_lexical_data = None
    email_analysis_data = None
    sandbox_report_obj = SandboxReport(
        sandbox_status="N/A",
        final_destination="N/A",
        screenshot_data="N/A"
    )

    cache_key = None
    backend = None

    # 1. GENERATE A UNIQUE CACHE KEY: Hash the incoming user inputs manually
    if phish.url:
        cache_key = f"url_scan:{phish.url.strip().lower()}"

        # 2. CHECK THE CACHE ENGINE
        backend = FastAPICache.get_backend()
        cached_value = await backend.get(cache_key)

        if cached_value is not None:
            # Cache Hit! Decode the JSON data straight out of memory
            # We don't append an "X-Cache" header here, which tells Streamlit it's a Hit!
            return json.loads(cached_value)

        # -------------------------------------------------------------
        # CACHE MISS PIPELINE: If no cache exists, run your core logic
        # -------------------------------------------------------------
        # Explicitly append the MISS header so Streamlit catches it
        response.headers.append("X-Cache", "MISS")

        if phish.run_sandbox:
            sandbox_result = await run_url_sandbox(phish.url)
            sandbox_report_obj.sandbox_status = sandbox_result["status"]
            sandbox_report_obj.screenshot_data = sandbox_result["screenshot_base64"]
            sandbox_report_obj.final_destination = sandbox_result["final_destination_url"]
        else:
            sandbox_report_obj.sandbox_status = "Skipped (User Opt-Out)"
            sandbox_report_obj.final_destination = phish.url
            sandbox_report_obj.screenshot_data = None

        # Process URL Lexical Analysis
        try:
            raw_lex = await assess_url_risk(phish.url)
            url_lexical_data = UrlLexicalAnalysis(**raw_lex)
        except Exception as e:
            url_lexical_data = UrlLexicalAnalysis(
                url=phish.url,
                verdict="ERROR",
                risk_score=1.0,
                reasons=[f"Lexical module failure: {str(e)}"]
            )

    # Process Email Text Keywords
    if phish.email_text:
        email_analysis_data = await check_email(phish.email_text)

    # Process External Threats Engine
    external_report_obj = ExternalReport(
        status="received" if phish.url else "empty",
        input_received=phish.url if phish.url else "Text Payload Only"
    )

    if phish.url:
        if VT_KEY:
            vt = await check_virustotal(phish.url, VT_KEY)
            if "error" in vt:
                external_report_obj.risk_level_from_virus_total = vt["error"]
                external_report_obj.engines_flagged_on_vt = 0
            else:
                external_report_obj.risk_level_from_virus_total = "Suspicious" if vt["total_risk"] > 0 else "Clean"
                external_report_obj.engines_flagged_on_vt = vt["total_risk"]

        if GOOGLE_KEY:
            google = await check_google_safe_browsing(phish.url, GOOGLE_KEY)
            external_report_obj.google_safe_browsing = "Malicious / Flagged" if google else "Clean"

    # Assemble local parameters
    local_report_obj = LocalReport(
        url_lexical_analysis=url_lexical_data,
        email_text_analysis=email_analysis_data
    )

    # Compile final structured response
    final_response = AnalysisResponse(
        local_report=local_report_obj,
        external_report=external_report_obj,
        sandbox=sandbox_report_obj
    )

    # 3. COMMIT TO CACHE MEMORY: Save this response object into RAM for 5 minutes (300 seconds)
    serialized_data = json.dumps(final_response.model_dump())
    await backend.set(cache_key, serialized_data, expire=300)

    return final_response

if __name__ == "__main__":
    import sys
    import asyncio

    # Ensure the policy is explicitly registered inside the main executing thread right at launch
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    # Force uvicorn to use the standard asyncio backend instead of its auto-selector
    uvicorn.run("main:app", host="0.0.0.0", port=8000, loop="asyncio", reload=True)