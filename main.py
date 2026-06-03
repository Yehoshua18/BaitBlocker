import uvicorn
import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
from fastapi.responses import RedirectResponse
from lexochecker import assess_url_risk
from interfaces import (check_google_safe_browsing, check_virustotal)
from emailchecker import TextPhishingAssessment, check_email

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

class LocalReport(BaseModel):
    url_lexical_analysis: Optional[UrlLexicalAnalysis] = None
    email_text_keyword_analysis: Optional[TextPhishingAssessment] = None

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

# This route listens to the main root page '/'
@app.get("/", include_in_schema=False)
async def redirect_to_docs():
    # Automatically redirects the user to the /docs endpoint
    return RedirectResponse(url="/docs")


@app.post(
    "/analyze",
    response_model=AnalysisResponse,
    status_code=200
)
async def analyze_input(phish: AnalysisRequest):
    if not phish.url and not phish.email_text:
        raise HTTPException(status_code=400, detail="Must provide a URL or email text.")

    # 1. Initialize holding variables as None/defaults instead of empty Pydantic objects
    url_lexical_data = None
    email_analysis_data = None

    # 2. Process URL Lexical Analysis
    if phish.url:
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

    # 3. Process Email Text Keywords (Populates straight from the awaited function)
    if phish.email_text:
        email_analysis_data = await check_email(phish.email_text)

    # 4. Process External Threats
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

    # 5. Build the LocalReport explicitly with the populated data objects
    local_report_obj = LocalReport(
        url_lexical_analysis=url_lexical_data,
        email_text_keyword_analysis=email_analysis_data  # <-- Directly bound on creation
    )

    # 6. Build the Master Response Object
    final_output = AnalysisResponse(
        local_report=local_report_obj,
        external_report=external_report_obj
    )

    return final_output

if __name__ == "__main__":

    uvicorn.run(app, host="0.0.0.0", port=8000)

   