from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Optional
import os
import httpx
import json
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

AGI_API_KEY = os.getenv("AGI_API_KEY")
AGI_BASE_URL = os.getenv("AGI_BASE_URL", "https://api.agi.tech")

# Jinja2 templates (backend is run from the backend/ folder)
templates = Jinja2Templates(directory="templates")

app = FastAPI(
    title="CyberRisk Advisor",
    description=(
        "CyberRisk Advisor is an AGI-powered cybersecurity copilot that analyzes raw logs, "
        "detects threats, scores overall risk, and generates incident-ready response plans. "
        "Built for the Vertical Agent Track of THE REAL AGENT CHALLENGE."
    ),
    version="1.0.0",
)

# Allow Lovable frontend / local dev to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # for hackathon simplicity; you can restrict later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------- Data Models ----------------------


class LogAnalysisRequest(BaseModel):
    """
    Input payload for CyberRisk Advisor.

    logs:        Raw log text or JSON (CloudTrail, Sysmon, Wazuh, auth logs, etc.)
    environment: Optional label for where the logs came from (AWS, GCP, Windows AD...)
    question:    Optional focus question from the analyst ("Is this lateral movement?")
    """

    logs: str
    environment: Optional[str] = None
    question: Optional[str] = None


class Detection(BaseModel):
    """
    A single detection / finding produced by the agent.
    """

    title: str
    description: str
    severity: str  # Low / Medium / High / Critical
    indicators: List[str]  # IPs, usernames, process names, etc.


class LogAnalysisResponse(BaseModel):
    """
    Structured response from CyberRisk Advisor.
    """

    overall_risk_score: float  # 0–100
    summary: str               # human-readable incident summary
    detections: List[Detection]
    recommended_actions: List[str]
    queries_to_run: List[str]  # follow-up SIEM queries (SPL, KQL, SQL-like)


# ---------------------- Helper: AGI API ----------------------
async def call_agi_agent(system_prompt: str, user_prompt: str) -> str:
    """
    Generic wrapper for calling the AGI API.

    NOTE: Adjust model name, endpoint path, and payload to match docs.agi.tech.
    """
    if not AGI_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="AGI_API_KEY is not configured on the server. Set it in backend/.env",
        )

    headers = {
        "Authorization": f"Bearer {AGI_API_KEY}",
        "Content-Type": "application/json",
    }

    # 🔹 This is the request body we send to AGI
    payload = {
        "model": "agi-latest",  # TODO: change to the exact model/agent name from AGI docs
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
    }

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"{AGI_BASE_URL}/v1/chat/completions",
            json=payload,
            headers=headers,
        )

        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            # 🔍 DEBUG: print everything from AGI so we see the real error
            print("=== AGI API DEBUG ===")
            print("Status code:", e.response.status_code)
            print("Response body:", e.response.text)
            print("Request payload:", payload)
            print("=====================")

            # Send the AGI error back to the frontend while we debug
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"AGI API error: {e.response.text}",
            )

        data = resp.json()
        # Adjust if AGI response format is different
        return data["choices"][0]["message"]["content"]

# ---------------------- UI Routes ----------------------


@app.get("/", response_class=HTMLResponse)
async def landing_page(request: Request):
    """
    Simple landing page for judges and teammates.
    """
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def health_check():
    """
    Health check endpoint (used by monitors / deployment).
    """
    return {"status": "ok"}


# ---------------------- Core API Route ----------------------


@app.post("/analyze_logs", response_model=LogAnalysisResponse, tags=["CyberRisk Advisor"])
async def analyze_logs(req: LogAnalysisRequest):
    """
    Main endpoint used by the Lovable frontend and any SOC tooling.
    """

    system_prompt = (
        "You are a senior security analyst and threat hunter assisting a SOC team. "
        "Given raw security logs, your job is to:\n"
        "- detect suspicious or malicious activity and group it into 'detections'\n"
        "- assign each detection a severity: Low / Medium / High / Critical\n"
        "- compute an overall risk score from 0 to 100 for the entire log batch\n"
        "- describe the situation in a concise summary (3–5 sentences)\n"
        "- propose concrete recommended_actions for the security team\n"
        "- output follow-up queries_to_run in a SIEM (SPL, KQL, SQL-like).\n\n"
        "Return ONLY valid JSON with this exact schema:\n"
        "{\n"
        '  \"overall_risk_score\": float,\n'
        '  \"summary\": str,\n'
        '  \"detections\": [\n'
        '    {\"title\": str, \"description\": str, \"severity\": str, \"indicators\": [str, ...]},\n'
        "  ],\n"
        '  \"recommended_actions\": [str, ...],\n'
        '  \"queries_to_run\": [str, ...]\n'
        "}"
    )

    user_prompt = f"""
    ENVIRONMENT:
    {req.environment or "Not specified"}

    ANALYST QUESTION / FOCUS:
    {req.question or "General threat hunting and incident triage."}

    LOGS:
    {req.logs}
    """

    raw_response = await call_agi_agent(system_prompt, user_prompt)

    # Try to parse the model output as JSON; handle common formatting issues
    try:
        result = json.loads(raw_response)
    except json.JSONDecodeError:
        cleaned = raw_response.strip().strip("`")
        cleaned = cleaned.replace("json", "", 1).strip()
        result = json.loads(cleaned)

    detections = [
        Detection(
            title=d.get("title", ""),
            description=d.get("description", ""),
            severity=d.get("severity", "Medium"),
            indicators=d.get("indicators", []),
        )
        for d in result.get("detections", [])
    ]

    return LogAnalysisResponse(
        overall_risk_score=result.get("overall_risk_score", 0.0),
        summary=result.get("summary", ""),
        detections=detections,
        recommended_actions=result.get("recommended_actions", []),
        queries_to_run=result.get("queries_to_run", []),
    )
