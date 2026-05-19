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
app = FastAPI(title="BaitBlocker Analysis Engine")

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
    # VirusTotal API v3 requires the URL to be sent as a data-form or via a specific endpoint
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VT_KEY
    }
    data = {"url": url}

    async with httpx.AsyncClient() as client:
        # Step 1: Submit the URL for analysis
        response = await client.post(api_url, headers=headers, data=data)

        if response.status_code == 401:
            return {"error": "Invalid VT API Key"}

        if response.status_code != 200:
            return {"error": "VT API Error", "details": response.text}

        # Step 2: Extract the analysis results
        # VT returns a summary of how many engines flagged the URL
        result_data = response.json()
        stats = result_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        # We look for 'malicious' or 'phishing' flags
        malicious_count = stats.get("malicious", 0)
        phishing_count = stats.get("phishing", 0)

        return {
            "malicious": malicious_count,
            "phishing": phishing_count,
            "total_risk": malicious_count + phishing_count
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
