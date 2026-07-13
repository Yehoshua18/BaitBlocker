import asyncio
import base64
import sys
from concurrent.futures import ThreadPoolExecutor

from playwright.async_api import async_playwright, ViewportSize
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


async def _execute_sandbox_logic(url: str) -> dict:
    """Core browser execution logic."""
    # Create a sandbox browser using Playwright's Chromium
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        viewport = ViewportSize(width=1280, height=720)
        context = await browser.new_context(
            viewport=viewport,
            # Use a very common user_agent string to avoid bot detection
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        page = await context.new_page()

        try:
            response = await page.goto(url, wait_until="networkidle", timeout=10000)
            # Give us the actual URL if the attacker encrypted it
            final_url = page.url
            screenshot_bytes = await page.screenshot(full_page=False)
            encoded_screenshot = base64.b64encode(screenshot_bytes).decode('utf-8')

            return {
                "status": "Success",
                "final_destination_url": final_url,
                "screenshot_base64": encoded_screenshot,
                "http_status": response.status if response else 200
            }
        except Exception as e:
            return {
                "status": "Failed",
                "final_destination_url": url,
                "screenshot_base64": None,
                "error_reason": f"Sandbox timeout or execution failure: {str(e)}"
            }
        finally:
            await context.close()
            await browser.close()


def _windows_worker_thread(url: str) -> dict:
    """
    Synchronous worker target that initializes its own separate thread loop
    and forces the Windows Proactor policy inside its isolated context.
    """
    # 1. Set the mandatory policy for this new thread
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    # 2. Open a fresh loop, run the logic to completion, and tear down cleanly
    return asyncio.run(_execute_sandbox_logic(url))


# Initialize a persistent thread pool to handle background execution
thread_pool = ThreadPoolExecutor(max_workers=3)


async def run_url_sandbox(url: str) -> dict:
    """
    Spins up an isolated, headless Chromium instance to inspect a URL.
    Handles Windows asyncio loop conflicts using a Python 3.7 compatible thread executor.
    """
    if sys.platform == 'win32':
        # Get the active FastAPI event loop running on the main thread
        loop = asyncio.get_event_loop()

        # Offload the worker task to our background ThreadPoolExecutor
        return await loop.run_in_executor(thread_pool, _windows_worker_thread, url)
    else:
        # Standard native async pathway for non-Windows systems
        return await _execute_sandbox_logic(url)