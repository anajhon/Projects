import os
import psutil

class BehavioralRuleEngine:
    def __init__(self, system_whitelist: list = None):
        self.system_whitelist = [name.lower() for name in (system_whitelist or [])]
        
        # Excluded binary substrings (e.g. legitimate setup/update binaries running from Temp)
        self.path_whitelist_binaries = [
            "codesetup",
            "update",
            "installer",
            "onedriveupdate"
        ]

    def evaluate_process(self, proc: psutil.Process) -> list:
        """
        Analyzes process runtime telemetry for suspicious indicators and anomalies.
        Returns a list of detected behavioral anomalies.
        """
        anomalies = []

        try:
            proc_name = proc.name().lower()
            
            # 1. Skip system whitelisted binaries immediately
            if proc_name in self.system_whitelist:
                return anomalies

            exe_path = ""
            try:
                exe_path = proc.exe().lower() if proc.exe() else ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe_path = ""

            cmdline_list = []
            try:
                cmdline_list = proc.cmdline()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmdline_list = []

            cmdline_str = " ".join(cmdline_list).lower() if cmdline_list else ""

            # ---------------------------------------------------------
            # RULE 1: PowerShell Obfuscation & Evasion (MITRE ATT&CK T1027)
            # ---------------------------------------------------------
            if proc_name in ["powershell.exe", "pwsh.exe"]:
                suspicious_flags = []
                
                # Check for script execution bypass
                if "-executionpolicy bypass" in cmdline_str or "-ep bypass" in cmdline_str:
                    suspicious_flags.append("-executionpolicy bypass")

                # Check for hidden window style
                if "-windowstyle hidden" in cmdline_str or "-w hidden" in cmdline_str:
                    suspicious_flags.append("-windowstyle hidden")

                # Check for encoded commands
                if "-encodedcommand" in cmdline_str or "-e " in cmdline_str or "-enc " in cmdline_str:
                    suspicious_flags.append("-encodedcommand")

                # Check for non-interactive switches often paired with payloads
                if "-noninteractive" in cmdline_str or "-noni" in cmdline_str:
                    suspicious_flags.append("-noninteractive")

                if len(suspicious_flags) >= 2:
                    anomalies.append({
                        "rule": "POWERSHELL_OBFUSCATION",
                        "mitre_id": "T1027",
                        "severity": "HIGH",
                        "description": f"Arguments d'évasion détectés : {', '.join(suspicious_flags)}"
                    })

            # ---------------------------------------------------------
            # RULE 2: Suspicious Execution Path (MITRE ATT&CK T1074)
            # ---------------------------------------------------------
            if exe_path:
                is_temp_path = "appdata\\local\\temp" in exe_path or "\\windows\\temp" in exe_path
                
                if is_temp_path:
                    # Ignore known legitimate software updaters
                    is_whitelisted_updater = any(w in proc_name for w in self.path_whitelist_binaries)

                    if not is_whitelisted_updater:
                        anomalies.append({
                            "rule": "SUSPICIOUS_EXECUTION_PATH",
                            "mitre_id": "T1074",
                            "severity": "MEDIUM",
                            "description": f"Exécution d'un binaire depuis un répertoire temporaire ({exe_path})."
                        })

            # ---------------------------------------------------------
            # RULE 3: Suspicious Command Shell Invocations (MITRE ATT&CK T1059)
            # ---------------------------------------------------------
            if proc_name in ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]:
                recon_keywords = ["whoami", "net user", "net localgroup", "systeminfo", "vssadmin"]
                matched_keywords = [kw for kw in recon_keywords if kw in cmdline_str]
                
                if matched_keywords:
                    anomalies.append({
                        "rule": "DISCOVERY_COMMAND_EXECUTION",
                        "mitre_id": "T1059",
                        "severity": "LOW",
                        "description": f"Commandes de reconnaissance détectées : {', '.join(matched_keywords)}"
                    })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return anomalies