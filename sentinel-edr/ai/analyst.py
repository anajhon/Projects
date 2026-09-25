import os
from google import genai

class AIIncidentAnalyst:
    def __init__(self, api_key: str):
        # Initialize the official Google GenAI client
        self.client = genai.Client(api_key=api_key)
        self.model_name = "gemini-2.5-flash"  # Fast, lightweight, and free tier friendly

    def explain_incident(self, incident_data: dict) -> str:
        try:
            proc = incident_data.get("process", {})
            intel = incident_data.get("threat_intelligence", {})
            anomalies = incident_data.get("behavioral_anomalies", [])
            action = incident_data.get("action_taken", "UNKNOWN")

            prompt = f"""
            You are an elite Senior SOC Incident Responder. Analyze this EDR security event intercepted by Sentinel EDR and provide a concise, hard-hitting 3-sentence executive briefing:
            
            - Target Process: {proc.get('name')} (PID: {proc.get('pid')}
            - SHA-256 Hash: {proc.get('sha256')}
            - VirusTotal Verdict: {intel.get('verdict')} (Score: {intel.get('score')})
            - Behavioral Anomalies: {anomalies}
            - Automated Enforcement Action: {action}
            
            Keep the tone professional, technical, and direct. Explain the potential impact and confirm the containment efficacy.
            """

            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
            )
            return response.text.strip()
            
        except Exception as e:
            return f"[!] AI Analysis Failed: {str(e)}"