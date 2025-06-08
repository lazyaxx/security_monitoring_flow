# tools/custom_tool.py
from crewai.tools import BaseTool
import requests
import re
from typing import Dict, List
import os
from urllib.parse import urlparse

class URLAnalyzerTool(BaseTool):
    name: str = "url_analyzer"  # ✅ Use snake_case consistently
    description: str = "Analyzes URLs for potential security threats and provides confidence scores"
    
    def _run(self, url: str) -> Dict:
        """Analyze a URL for security threats"""
        try:
            # Your existing analysis logic here
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                return {
                    "url": url,
                    "confidence_score": 0.9,
                    "threat_indicators": ["Invalid URL format"],
                    "assessment": "malicious",
                    "details": "URL format is invalid"
                }
            
            threat_indicators = []
            confidence_score = 0.0
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'\.exe$', r'\.scr$', r'\.bat$', r'\.com$',
                r'phishing', r'malware', r'virus', r'hack'
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    threat_indicators.append(f"Suspicious pattern: {pattern}")
                    confidence_score += 0.2
            
            # Check domain reputation
            domain = parsed_url.netloc.lower()
            malicious_domains = ['malware.com', 'phishing-site.net']
            
            if any(bad_domain in domain for bad_domain in malicious_domains):
                threat_indicators.append("Known malicious domain")
                confidence_score += 0.5
            
            # Check for HTTPS
            if parsed_url.scheme != 'https':
                threat_indicators.append("Non-HTTPS connection")
                confidence_score += 0.1
            
            confidence_score = min(confidence_score, 1.0)
            
            if confidence_score > 0.7:
                assessment = "malicious"
            elif confidence_score > 0.3:
                assessment = "suspicious"
            else:
                assessment = "benign"
            
            return {
                "url": url,
                "confidence_score": confidence_score,
                "threat_indicators": threat_indicators,
                "assessment": assessment,
                "details": f"Analysis completed with {len(threat_indicators)} indicators"
            }
            
        except Exception as e:
            return {
                "url": url,
                "confidence_score": 0.5,
                "threat_indicators": [f"Analysis error: {str(e)}"],
                "assessment": "unknown",
                "details": "Error during analysis"
            }

class SOCCommunicationTool(BaseTool):
    name: str = "soc_communicator"  # ✅ Consistent naming
    description: str = "Communicates with SOC admin server for severity assessment"
    
    def _run(self, analysis_data: str) -> Dict:  # ✅ Accept string input from context
        """Send analysis to SOC admin and get severity assessment"""
        try:
            # Parse analysis data from context
            if "malicious" in analysis_data.lower():
                confidence_score = 0.8
                assessment = "malicious"
            elif "suspicious" in analysis_data.lower():
                confidence_score = 0.5
                assessment = "suspicious"
            else:
                confidence_score = 0.2
                assessment = "benign"
            
            soc_url = os.getenv("SOC_ADMIN_URL", "http://localhost:8001")
            
            payload = {
                "url": "parsed_from_context",
                "confidence_score": confidence_score,
                "threat_indicators": [],
                "agent_assessment": assessment
            }
            
            # Simulate SOC response for demo
            if confidence_score > 0.7:
                return {
                    "soc_severity": "high",
                    "soc_action": "block",
                    "soc_reason": "High threat confidence detected",
                    "communication_status": "success"
                }
            elif confidence_score > 0.3:
                return {
                    "soc_severity": "medium", 
                    "soc_action": "review",
                    "soc_reason": "Medium threat requires review",
                    "communication_status": "success"
                }
            else:
                return {
                    "soc_severity": "low",
                    "soc_action": "allow",
                    "soc_reason": "Low threat confidence",
                    "communication_status": "success"
                }
                
        except Exception as e:
            return {
                "soc_severity": "unknown",
                "soc_action": "review", 
                "soc_reason": f"SOC communication error: {str(e)}",
                "communication_status": "error"
            }

class GatekeeperTool(BaseTool):
    name: str = "gatekeeper_monitor"  # ✅ Consistent naming
    description: str = "Monitors agent communications and blocks unwanted activities"
    
    def _run(self, context: str) -> Dict:
        """
        Monitors agent communications and makes final security decisions.
        Provides complete decision - no additional analysis needed.
        """
        try:
            context_lower = context.lower()
            
            decision_summary = """
    🛡️ GATEKEEPER SECURITY DECISION COMPLETE 🛡️

    ANALYSIS REVIEW:
    """
            
            # Rule 1: Block exe downloads marked as benign
            if ".exe" in context_lower and "benign" in context_lower:
                decision_summary += """
    ⚠️ SECURITY VIOLATION DETECTED: Executable download classified as benign
    🚫 GATEKEEPER ACTION: BLOCK (Override Agent A decision)
    📋 REASON: Security policy violation - executable downloads require strict scrutiny
    ✅ FINAL DECISION: ACCESS DENIED

    🔒 SECURITY POLICY ENFORCED ✅
    NO FURTHER ANALYSIS REQUIRED
    """
                return decision_summary
            
            # Rule 2: Block high confidence malicious marked as allow
            if ("malicious" in context_lower or "suspicious" in context_lower) and "allow" in context_lower:
                decision_summary += """
    ⚠️ SECURITY VIOLATION DETECTED: Malicious content marked for allow
    🚫 GATEKEEPER ACTION: BLOCK (Override SOC decision) 
    📋 REASON: High threat confidence conflicts with allow recommendation
    ✅ FINAL DECISION: ACCESS DENIED

    🔒 SECURITY POLICY ENFORCED ✅
    NO FURTHER ANALYSIS REQUIRED
    """
                return decision_summary
            
            # Rule 3: Approve blocking decisions
            if "block" in context_lower:
                decision_summary += """
    ✅ SECURITY ASSESSMENT: Blocking decision confirmed
    🛡️ GATEKEEPER ACTION: APPROVE (Confirm SOC decision)
    📋 REASON: Threat assessment and blocking recommendation are aligned
    ✅ FINAL DECISION: BLOCK CONFIRMED

    🔒 SECURITY POLICY MAINTAINED ✅
    NO FURTHER ANALYSIS REQUIRED
    """
                return decision_summary
            
            # Default: Allow with monitoring
            decision_summary += """
    ✅ SECURITY ASSESSMENT: No policy violations detected
    🛡️ GATEKEEPER ACTION: APPROVE (Follow SOC recommendation)
    📋 REASON: Security analysis and recommendations are consistent
    ✅ FINAL DECISION: PROCEED AS RECOMMENDED

    🔒 SECURITY STANDARDS MAINTAINED ✅
    NO FURTHER ANALYSIS REQUIRED
    """
            
            return decision_summary
            
        except Exception as e:
            return f"""
    ❌ GATEKEEPER ERROR: Decision analysis failed
    📋 ERROR DETAILS: {str(e)}
    🛡️ FALLBACK ACTION: REVIEW REQUIRED
    ✅ FINAL DECISION: MANUAL SECURITY REVIEW NEEDED

    ⚠️ ESCALATE TO SECURITY TEAM ⚠️
    """
