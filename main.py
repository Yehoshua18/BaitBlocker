import base64
import uvicorn
import httpx
import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
from fastapi.responses import RedirectResponse

#from database import init_db, add_single_keyword, add_bulk_keywords, get_all_keywords
from lexochecker import assess_url_risk

#load keys from .env
load_dotenv()

#Initialize the App
app = FastAPI(
    title="BaitBlocker Analysis Engine",
    description="Lexicographical & External Threat Intelligence Engine",
    version="1.0.0",
    # Pass a dictionary of Swagger UI configuration parameters
    swagger_ui_parameters={
        "defaultModelsExpandDepth": -1,  # Hides the ugly "Schemas" section at the bottom
        "deepLinking": True,
        "displayRequestDuration": True,  # Shows how fast your endpoints run in milliseconds
        "docExpansion": "list"           # Keeps endpoints cleanly listed but closed by default
    })

#We'll be using 2 databases - Google Safe and VirusTotal
GOOGLE_KEY = os.getenv("GOOGLE_API_KEY")
VT_KEY = os.getenv("VT_API_KEY")

#double check keys were loaded
@app.get("/test-keys")
async def test_keys():
    return {"google_loaded": bool(GOOGLE_KEY), "vt_loaded": bool(VT_KEY)}

# --- REQUEST SCHEMA ---
class AnalysisRequest(BaseModel):
    # Enforcing clean primitive types (Optional strings)
    url: Optional[str] = Field(None, examples=["https://signin-netflix.xyz"])
    email_text: Optional[str] = Field(None, examples=["Urgent: update your invoice billing info."])

# --- RESPONSE SUB-SCHEMAS ---
class UrlLexicalAnalysis(BaseModel):
    url: str
    verdict: str
    risk_score: float
    reasons: List[str]

class KeywordMatch(BaseModel):
    keyword: str
    weight: float

class EmailTextAnalysis(BaseModel):
    status: str
    combined_risk_weight: float
    matches_found: List[KeywordMatch]

class LocalReport(BaseModel):
    url_lexical_analysis: Optional[UrlLexicalAnalysis] = None
    email_text_keyword_analysis: Optional[EmailTextAnalysis] = None

class ExternalReport(BaseModel):
    status: str
    input_received: str
    google_safe_browsing: Optional[str] = None
    risk_level_from_virus_total: Optional[str] = None
    engines_flagged_on_vt: Optional[int] = None

# --- MASTER RESPONSE SCHEMA ---
class AnalysisResponse(BaseModel):
    local_report: LocalReport
    external_report: ExternalReport

async def check_google_safe_browsing(url: str):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_KEY}"
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}] #insert our URL into the safebrowsing API
        }
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(api_url, json=payload)
        data = response.json()
        # If 'matches' exists in the response, the URL is malicious
        return "matches" in data


async def check_virustotal(url: str):
    # 1. Clean the string and encode to standard Base64
    url_bytes = url.strip().encode("utf-8")

    # urlsafe encoding ensures '+' and '/' are safe for the URL path
    base64_encoded = base64.urlsafe_b64encode(url_bytes).decode("utf-8")

    # CRITICAL: VirusTotal requires you to completely strip any trailing '=' padding
    url_id = base64_encoded.rstrip("=")

    # 2. Query the URL repository directly via GET
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_KEY
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(api_url, headers=headers)
        print("VT STATUS CODE:", response.status_code)
        print("RAW DATA SAMPLE:", response.text[:500])  # Look at the first 500 characters

        if response.status_code == 401:
            return {"error": "Invalid VT API Key"}

        # 404 means the URL has never been submitted to VirusTotal by anyone before
        if response.status_code == 404:
            return {"malicious": 0, "suspicious": 0, "total_risk": 0, "note": "Clean / Unscanned URL"}

        if response.status_code != 200:
            return {"error": "VT API Error", "details": response.text}

        result_data = response.json()

        # 3. Pull from the persistent analysis matrix
        stats = result_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)

        return {
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "total_risk": malicious_count + suspicious_count
        }

# This route listens to the main root page '/'
@app.get("/", include_in_schema=False)
async def redirect_to_docs():
    # Automatically redirects the user to the /docs endpoint
    return RedirectResponse(url="/docs")


@app.post(
    "/analyze",
    response_model=AnalysisResponse,  # Tells FastAPI to validate the outbound structure
    status_code=200
)
async def analyze_input(phish: AnalysisRequest):
    if not phish.url and not phish.email_text:
        raise HTTPException(status_code=400, detail="Must provide a URL or email text.")

    # 1. Initialize Pydantic models with baseline safe defaults
    local_report_obj = LocalReport()

    external_report_obj = ExternalReport(
        status="empty",
        input_received=phish.url if phish.url else "Text Payload Only"
    )

    # 2. Process URL Lexical Analysis
    if phish.url:
        try:
            raw_lex = await assess_url_risk(phish.url)
            # Explicitly parse the raw dictionary into the target Pydantic sub-model
            local_report_obj.url_lexical_analysis = UrlLexicalAnalysis(**raw_lex)
        except Exception as e:
            local_report_obj.url_lexical_analysis = UrlLexicalAnalysis(
                url=phish.url,
                verdict="ERROR",
                risk_score=1.0,
                reasons=[f"Lexical module failure: {str(e)}"]
            )

    # 3. Process Email Text Keywords
    if phish.email_text:
        # (Assuming you ran your database loops here and generated 'matches' and 'total_weight')
        detected_matches = [KeywordMatch(keyword="signin", weight=0.5)]  # Example payload

        local_report_obj.email_text_keyword_analysis = EmailTextAnalysis(
            status="Analyzed",
            combined_risk_weight=0.5,
            matches_found=detected_matches
        )

    # 4. Process External Threats (Google/VT Example updates)
    if phish.url and VT_KEY:
        external_report_obj.status = "received"
        external_report_obj.google_safe_browsing = "Clean"
        external_report_obj.risk_level_from_virus_total = "Suspicious"
        external_report_obj.engines_flagged_on_vt = 1

    # 5. Build the Master Object explicitly mapping fields
    final_output = AnalysisResponse(
        local_report=local_report_obj,
        external_report=external_report_obj
    )

    # Returning a native Pydantic model satisfies PyCharm's strict Type-Checker completely
    return final_output

if __name__ == "__main__":

    uvicorn.run(app, host="0.0.0.0", port=8000)

   