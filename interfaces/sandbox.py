import base64
import sys
from concurrent.futures import ThreadPoolExecutor
import asyncio
from playwright.async_api import async_playwright, ViewportSize


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