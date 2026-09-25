import json
import logging
from datetime import datetime, timezone
from pathlib import Path
import psutil

try:
    from core.firewall import FirewallIsolation
except ImportError:
    from firewall import FirewallIsolation

class ContainmentEngine:
    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def handle_incident(self, proc: psutil.Process, anomalies: list, intel_result: dict, file_hash: str, active_ips: list = None) -> dict:
        action_taken = "UNKNOWN"
        pid = proc.pid
        name = "unknown"
        active_ips = active_ips or []

        try:
            name = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # 1. Immediate isolation: Suspend process execution
        try:
            proc.suspend()
            logging.info(f"Process PID {pid} ({name}) suspended for inspection.")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # 2. Decision Logic: Terminate on MALICIOUS reputation OR HIGH severity rule
        is_malicious_reputation = intel_result.get("verdict") == "MALICIOUS"
        has_high_severity_rule = any(anomaly.get("severity") == "HIGH" for anomaly in anomalies)

        if is_malicious_reputation or has_high_severity_rule:
            try:
                proc.kill()
                action_taken = "KILLED"
                logging.warning(f"[CONTAINMENT] Terminated PID {pid} ({name}) due to severe threat policy!")
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                action_taken = f"FAILED_TO_KILL ({str(e)})"

            # 3. Active Response: Block associated remote C2 IP addresses
            blocked_ips = []
            for ip in active_ips:
                if FirewallIsolation.block_remote_ip(ip):
                    blocked_ips.append(ip)

            if blocked_ips:
                action_taken = "KILLED_AND_ISOLATED"
        else:
            try:
                proc.resume()
                action_taken = "RESUMED"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # 4. Structured Telemetry Logging (JSONL)
        event_record = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_type": "EDR_DETECTION",
            "action_taken": action_taken,
            "process": {
                "pid": pid,
                "name": name,
                "sha256": file_hash
            },
            "network": {
                "remote_ips": active_ips
            },
            "threat_intelligence": intel_result,
            "behavioral_anomalies": anomalies
        }

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_record) + "\n")
        except OSError as e:
            logging.error(f"Failed to record event log: {e}")

        return event_record