from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

# 1. Initialize the App
app = FastAPI(title="PhishGuard Analysis Engine")


# 2. Define the Request Schema
class AnalysisRequest(BaseModel):
    url: Optional[str] = None
    email_text: Optional[str] = None


# 3. Create the Analysis Endpoint
@app.post("/analyze")
async def analyze_input(request: AnalysisRequest):
    # Validation logic
    if not request.url and not request.email_text:
        raise HTTPException(status_code=400, detail="Must provide a URL or email text.")

    # Placeholder for your "Brain" (Phases 2 & 3)
    results = {
        "status": "received",
        "input_received": request.url or "Text Block",
        "risk_score": 0.0,  # This will be calculated by your ML models
        "recommendation": "Pending analysis"
    }

    return results


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
