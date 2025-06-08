# main.py
import os
import json
from typing import Dict, List, Any
from crewai.flow.flow import Flow, listen, start
from pydantic import BaseModel
from crews.security_crew.security_crew import SecurityCrew
from dotenv import load_dotenv

load_dotenv()

class SecurityState(BaseModel):
    processed_urls: List[str] = []
    results: List[Dict] = []

class SecurityMonitoringFlow(Flow[SecurityState]):
    """Multi-agent security monitoring flow for URL analysis"""
    
    def __init__(self):
        super().__init__()
        self.security_crew = SecurityCrew()
        
    @start()
    def initialize_monitoring(self):
        """Initialize the security monitoring system"""
        print("🚀 Starting Security Monitoring System")
        print("=" * 50)
        
        # Demo URL list
        demo_urls = [
            "https://example.com",
            "https://malware.com/download.exe", 
            "https://phishing-site.net/fake-login",
            "https://legitimate-site.org",
            "https://suspicious-download.org/file.exe",
            "http://unsecure-site.com"
        ]
        
        return {"urls_to_process": demo_urls}
    
    @listen(initialize_monitoring)
    def process_urls(self, data):
        """Process each URL through the security crew using kickoff_for_each"""
        urls = data["urls_to_process"]
        
        print(f"\n🔍 Processing {len(urls)} URLs...")
        
        # ✅ Use kickoff_for_each for efficient batch processing
        # Prepare inputs for each URL
        url_inputs = [{"url": url} for url in urls]
        
        # Process all URLs using kickoff_for_each
        results = self.security_crew.crew().kickoff_for_each(inputs=url_inputs)
        
        # Store results
        for i, (url, result) in enumerate(zip(urls, results)):
            print(f"✅ Completed processing: {url}")
            
            self.state.processed_urls.append(url)
            self.state.results.append({
                "url": url,
                "result": str(result),
                "crew_result": result  # Store the actual CrewAI result object
            })
            
            print(f"   Status: {'Success' if result else 'Failed'}")
            print("-" * 50)
        
        return {"completed": True, "total_processed": len(results)}
    
    @listen(process_urls)
    def generate_summary_report(self, data):
        """Generate final summary report"""
        print("\n📊 SECURITY MONITORING SUMMARY")
        print("=" * 60)
        print(f"URLs Processed: {len(self.state.processed_urls)}")
        print(f"Total Completed: {data['total_processed']}")
        
        # Enhanced reporting with security decisions
        blocked_urls = []
        allowed_urls = []
        review_urls = []
        
        for i, result in enumerate(self.state.results, 1):
            result_str = result['result'].lower()
            url = result['url']
            
            print(f"\n{i}. {url}")
            
            # Extract security decision from result
            if 'block' in result_str:
                blocked_urls.append(url)
                print(f"   🚫 Decision: BLOCKED")
            elif 'allow' in result_str:
                allowed_urls.append(url)
                print(f"   ✅ Decision: ALLOWED")
            elif 'review' in result_str:
                review_urls.append(url)
                print(f"   🔍 Decision: REVIEW REQUIRED")
            else:
                print(f"   ❓ Decision: UNKNOWN")
            
            print(f"   Summary: {result['result'][:100]}...")
        
        # Final security summary
        print(f"\n🛡️  SECURITY SUMMARY:")
        print(f"   🚫 Blocked: {len(blocked_urls)} URLs")
        print(f"   ✅ Allowed: {len(allowed_urls)} URLs") 
        print(f"   🔍 Review Required: {len(review_urls)} URLs")
        
        if blocked_urls:
            print(f"\n🚫 BLOCKED URLS:")
            for url in blocked_urls:
                print(f"   - {url}")
        
        return {
            "summary": "Security monitoring completed",
            "stats": {
                "total": len(self.state.processed_urls),
                "blocked": len(blocked_urls),
                "allowed": len(allowed_urls),
                "review": len(review_urls)
            }
        }

def run_security_monitoring():
    """Run the security monitoring system"""
    flow = SecurityMonitoringFlow()
    result = flow.kickoff()
    return result

if __name__ == "__main__":
    run_security_monitoring()
