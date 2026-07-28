import base64
import httpx

async def check_google_safe_browsing(url: str, key: str):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}] # Insert our URL into the safebrowsing API
        }
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(api_url, json=payload)
        data = response.json()
        # If 'matches' exists in the response, the URL is malicious
        return "matches" in data

async def check_virustotal(url: str, key: str):
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
        "x-apikey": key
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