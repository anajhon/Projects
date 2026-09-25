import requests
import logging

class VirusTotalClient:
    def __init__(self, api_key: str, endpoint_url: str, threshold: int = 3, cache_ttl: int = 24):
        self.api_key = api_key
        # Assure la présence du slash final
        self.endpoint_url = endpoint_url if endpoint_url.endswith("/") else f"{endpoint_url}/"
        self.threshold = threshold
        self.cache_ttl = cache_ttl
        self.cache = {}
        self.headers = {
            "x-apikey": self.api_key,
            "accept": "application/json"
        }

    def query_hash(self, sha256: str) -> dict:
        if not sha256:
            return {"verdict": "UNKNOWN", "score": 0, "status": "Invalid Hash"}

        if sha256 in self.cache:
            return self.cache[sha256]

        if not self.api_key or self.api_key == "YOUR_ACTUAL_API_KEY_PASTED_HERE":
            return {"verdict": "SKIPPED", "score": 0, "status": "No API Key Configured"}

        target_url = f"{self.endpoint_url}{sha256}"

        try:
            response = requests.get(
                target_url,
                headers=self.headers,
                timeout=10
            )

            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total_threat_score = malicious + suspicious

                verdict = "MALICIOUS" if total_threat_score >= self.threshold else "BENIGN"
                result = {
                    "verdict": verdict,
                    "score": total_threat_score,
                    "status": "Report Found"
                }
                self.cache[sha256] = result
                return result

            elif response.status_code == 404:
                return {"verdict": "UNKNOWN", "score": 0, "status": "Hash Not Found on VT"}
            elif response.status_code == 401:
                return {"verdict": "ERROR", "score": 0, "status": "Invalid API Key (401)"}
            elif response.status_code == 429:
                return {"verdict": "ERROR", "score": 0, "status": "Quota Exceeded (429)"}
            else:
                return {"verdict": "ERROR", "score": 0, "status": f"HTTP Error {response.status_code}"}

        except requests.exceptions.SSLError as e:
            return {"verdict": "ERROR", "score": 0, "status": f"SSL Error: {e}"}
        except requests.exceptions.ConnectionError as e:
            return {"verdict": "ERROR", "score": 0, "status": f"Connection Error (DNS/Firewall): {e}"}
        except requests.exceptions.Timeout:
            return {"verdict": "ERROR", "score": 0, "status": "Request Timeout"}
        except requests.RequestException as e:
            return {"verdict": "ERROR", "score": 0, "status": f"Network Error: {e}"}