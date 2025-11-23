# 🛡️ CyberRisk Advisor – AI-Powered Log Triage Copilot

**Vertical Agent • CyberRisk Advisor • THE REAL AGENT CHALLENGE**

CyberRisk Advisor is an AI-powered security copilot that ingests raw security logs (CloudTrail, Sysmon, auth logs, etc.), detects threats, assigns an overall risk score, and generates incident-ready response guidance for SOC analysts.

The goal: **turn noisy logs into clear, actionable decisions in seconds**.

---

## ⚡ What this Agent Does

Given a batch of logs and a short question or focus area, the agent:

1. **Parses raw logs** (plain text / JSON).
2. **Identifies detections**  
   - Suspicious sign-ins  
   - Privilege escalation  
   - Lateral movement  
   - Crypto-mining, brute force, etc.  
3. **Scores overall risk** from **0–100** for the entire batch.
4. **Summarizes the incident** in 3–5 sentences.
5. **Recommends concrete actions** for the SOC team.
6. Suggests **follow-up SIEM queries** (SPL / KQL / SQL-like) to deepen the investigation.

All of this is returned as structured JSON so it can plug into dashboards or other tools.

---

## 🧩 Architecture

**High-level flow:**

1. **Front-end log console (index.html)**  
   - Dropdowns for environment context (e.g., `AWS Production`).  
   - Dropdown for analyst concern (e.g., `credential theft / crypto mining`).  
   - Large textarea to paste raw logs.  
   - “Analyze Logs” button + live character counter.  
   - Results panel showing risk score, summary, detections, actions, and queries.

2. **FastAPI backend (`main.py`)**
   - Exposes `POST /analyze_logs` endpoint.
   - Accepts logs + environment + optional question.
   - Crafts a **security-analyst system prompt** and user prompt.
   - Calls the **AGI API** (LLM) for reasoning.

3. **AGI LLM**
   - Reads prompts + raw log payload.
   - Returns **strict JSON** with:
     - `overall_risk_score`
     - `summary`
     - `detections[]`
     - `recommended_actions[]`
     - `queries_to_run[]`

4. **UI**
   - Renders the JSON back into:
     - Big risk score (`82.5 / 100`)
     - Human-readable summary
     - Cards for each detection (title, severity, indicators)
     - Bullet list of recommended actions
     - Code-style blocks for SIEM queries

---

## 📁 Project Structure

```text
CyberRisk-Advisor/
├── AGI-1.mov           # Demo video (local run / proof of concept)
├── index.html          # Front-end UI (log console + results panel)
├── main.py             # FastAPI backend + /analyze_logs endpoint
└── requirements.txt    # Python dependencies



---

## 🏗️ Tech Stack

- **Backend:** FastAPI (Python)
- **Frontend:** HTML + CSS + vanilla JavaScript (single-page UI)
- **LLM Provider:** AGI API (OpenAI-style interface)
- **Infra:** Uvicorn (local dev), `.env` configuration

---


## 👩‍💻 Author

Gouthami Nadupuri

Data Scientist | AI Engineer | Creator of CurioGalaxy 💫

🔗 LinkedIn: https://www.linkedin.com/in/gouthami-nadupuri

🔗 GitHub: https://github.com/GouthamiN25


