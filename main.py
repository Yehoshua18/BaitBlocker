import base64

import httpx
import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from fastapi.responses import RedirectResponse
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

#Define the Request Schema - check the URL and the text itself
class AnalysisRequest(BaseModel):
    url: Optional[str] = None
    email_text: Optional[str] = None

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

# Create the Analysis Endpoint
@app.post("/analyze")
async def analyze_input(phish: AnalysisRequest):
    # Validation logic
    if not phish.url and not phish.email_text:
        raise HTTPException(status_code=400, detail="Must provide a URL or email text.")

    lex_analysis = assess_url_risk(phish.url)
    external_report = {
        "status": "empty",
        "input_received": phish.url or "Text Block"
    }
    # Perform the checks
    if GOOGLE_KEY or VT_KEY:
        external_report["status"] = "received"
        if GOOGLE_KEY:
            is_malicious = await check_google_safe_browsing(phish.url)
            external_report.update({"google_safe_browsing": "Malicious" if is_malicious else "Clean"})
        if VT_KEY:
            vt_results = await check_virustotal(phish.url)
            # Simple logic: if more than 1 engine flags it, we call it "High Risk"
            risk_level = "Safe"
            if vt_results.get("total_risk", 0) > 0:
                risk_level = "Suspicious"
            if vt_results.get("total_risk", 0) > 3:
                risk_level = "High Risk"

            external_report.update({
                "risk_level_from_virus_total": risk_level, #risk based on VT
                "engines_flagged_on_vt": vt_results.get("total_risk"), #to know why the risk is high
                "recommendation": "Pending analysis"
            })

    final_report = {
        "local_report": lex_analysis,
        "external_report": external_report
    }

    return final_report


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
