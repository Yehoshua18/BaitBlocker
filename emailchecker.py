import json
import os
from typing import List, Optional, Any, cast

from dotenv import load_dotenv
from openai import AsyncOpenAI
from pydantic import BaseModel, Field

load_dotenv()

AI_KEY = os.getenv("GROK_KEY")


class TextPhishingAssessment(BaseModel):
    phishing_probability: float = Field(
        ...,
        description="A score from 0.0 (completely safe) to 1.0 (definitely phishing/malicious)."
    )
    risk_level: str = Field(
        ...,
        description="The overall risk category. Must be one of: Safe, Low, Medium, High."
    )
    red_flags: List[str] = Field(
        ...,
        description="List of specific indicators found (e.g., 'Urgent tone', 'Spoofed domain lookalike', 'Credential harvesting attempt')."
    )
    summary_analysis: str = Field(
        ...,
        description="A brief paragraph explaining the reasoning behind the assessment."
    )
    recommended_action: str = Field(
        ...,
        description="Action for the mail system to take: 'Deliver', 'Flag/Warn User', or 'Quarantine'."
    )


async def check_email(email: str) -> Optional[TextPhishingAssessment]:
    client = AsyncOpenAI(
        base_url="https://api.groq.com/openai/v1",
        api_key=AI_KEY
    )
    system_prompt = (
        "You are an expert Cyber Security Operations Center (SOC) analyst specializing in email security. "
        "Analyze the provided email text for social engineering, phishing, or Business Email Compromise (BEC) tactics.\n\n"
        "You MUST respond ONLY with a raw JSON object matching this exact schema layout:\n"
        "{\n"
        '  "phishing_probability": float (0.0 to 1.0),\n'
        '  "risk_level": "Safe" | "Low" | "Medium" | "High",\n'
        '  "red_flags": ["reason1", "reason2"],\n'
        '  "summary_analysis": "your string summary here",\n'
        '  "recommended_action": "Deliver" | "Flag/Warn User" | "Quarantine"\n'
        "}\n\n"
        "Evaluate the text specifically for:\n"
        "1. Urgency/Fear: Pressuring the user to act quickly.\n"
        "2. Authority/Brand Impersonation: Posing as a boss, IT support, bank, or vendor.\n"
        "3. Credential Harvesting: Attempting to steer the user toward updating passwords or logging in.\n"
        "4. Anomalous Requests: Asking for gift cards, wire transfers, or sensitive data.\n"
        "5. Bot Detection: Unhuman-like typing."
    )

    try:
        messages_payload = cast(Any, [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Review this email:\n\n{email}"}
        ])

        response = await client.chat.completions.create(
            model="qwen/qwen3-32b",
            messages=messages_payload,
            response_format=cast(Any,{"type": "json_object"}),
            temperature=0.6
        )

        # 1. Extract the raw text string containing the JSON
        raw_content = response.choices[0].message.content

        # 2. Parse string into standard dictionary
        parsed_json = json.loads(raw_content)

        # 3. Explicitly construct and return the Pydantic validator model
        return TextPhishingAssessment(**parsed_json)

    except Exception as e:
        print(f"Error during API call or parsing: {e}")
        return TextPhishingAssessment(
        phishing_probability=0.0,
        risk_level="High",
        red_flags=["API Error Encountered"],
        summary_analysis="The AI analysis could not execute. Check server logs and API quotas.",
        recommended_action="Flag/Warn User"
    )
