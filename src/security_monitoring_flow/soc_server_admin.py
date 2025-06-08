# soc_admin_server.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import random

app = FastAPI(title="SOC Admin Server")

class URLAnalysis(BaseModel):
    url: str
    confidence_score: float
    threat_indicators: list
    agent_assessment: str

class SeverityResponse(BaseModel):
    severity: str  # "low", "medium", "high"
    action: str    # "allow", "block", "review"
    reason: str

# Simulated threat database
KNOWN_THREATS = {
    "malware.com": "high",
    "phishing-site.net": "high", 
    "suspicious-download.org": "medium",
    "fake-bank.com": "high"
}

@app.post("/assess_severity", response_model=SeverityResponse)
async def assess_severity(analysis: URLAnalysis):
    """SOC Admin endpoint to assess URL severity"""
    
    # Check against known threats
    domain = analysis.url.split("//")[-1].split("/")[0]
    
    if domain in KNOWN_THREATS:
        severity = KNOWN_THREATS[domain]
    else:
        # Simulate analysis based on confidence score and indicators
        if analysis.confidence_score > 0.8:
            severity = "high"
        elif analysis.confidence_score > 0.5:
            severity = "medium"  
        else:
            severity = "low"
    
    # Determine action
    if severity == "high":
        action = "block"
        reason = f"High threat confidence: {analysis.confidence_score}"
    elif severity == "medium":
        action = "review"
        reason = f"Medium threat requires review: {analysis.confidence_score}"
    else:
        action = "allow"
        reason = f"Low threat confidence: {analysis.confidence_score}"
    
    return SeverityResponse(
        severity=severity,
        action=action,
        reason=reason
    )

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
