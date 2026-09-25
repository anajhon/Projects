# SENTINEL EDR
**Active Defense & AI Incident Command Console**

Sentinel EDR is a lightweight, fully functional Endpoint Detection and Response (EDR) agent built in Python. It features a high-contrast minimalist "Obsidian Vertex" command interface, real-time behavioral monitoring, cloud-based threat intelligence, automated process containment, and an integrated AI Neural Threat Analyst that synthesizes telemetry into technical executive briefings in real-time.

---

## 🚀 Key Features

* **Real-Time Behavioral Heuristics:** Monitors active processes, process hierarchies, and command-line execution arguments to identify adversarial techniques (e.g., MITRE ATT&CK T1027 - Obfuscated Files or Information, PowerShell security policy bypasses).
* **Automated Threat Containment:** Instantly suspends and terminates high-severity malicious processes before destructive payloads can execute.
* **Network Isolation:** Inspects active outbound network sockets to extract remote C2 (Command and Control) IP addresses and block them via Windows Firewall rules.
* **Cloud Threat Intelligence:** Integrates with the VirusTotal v3 API to perform automated hash reputation lookups on running binaries with local caching.
* **AI Neural Threat Analyst (Groq / Qwen 27B):** Leverages Groq LPUs to synthesize process metadata, MITRE techniques, and behavioral indicators into an executive-level forensic analysis report.
* **Obsidian Vertex UI:** Built with `customtkinter`, featuring zero-distraction layout ergonomics, an animated targeting reticle canvas, and a pulsing wireframe diamond neural core.

---

## 🛠️ Architecture & Tech Stack

* **Language:** Python 3.10+ (Windows 10/11 Recommended)
* **GUI Framework:** CustomTkinter (`customtkinter`)
* **Process & Socket Telemetry:** `psutil`
* **Network & API Handlers:** `requests`
* **Inference Engine:** Groq Cloud API (`qwen/qwen3.8-27b`)
* **Threat Intelligence:** VirusTotal API v3

---

## 📂 Project Structure

mini-edr/
├── README.md                   # Project documentation
├── requirements.txt            # Python dependencies
├── main.py                     # EDR telemetry loop & Obsidian Vertex UI
├── core/
│   ├── containment.py          # Process suspension, termination, and triage handler
│   └── firewall.py             # Windows Firewall isolation rules
├── rules/
│   └── heuristics.py           # Behavioral rules engine (MITRE ATT&CK mapping)
├── intel/
│   └── virus_total.py          # VirusTotal hash analysis & cache manager
├── config/
│   └── settings.json           # Agent configuration, thresholds, and whitelists
├── tests/
│   └── malicious.py            # Safe adversary emulation script
└── logs/
    └── edr_events.json         # Structured forensic event logs

---

## ⚙️ Installation & Setup

**1. Clone the repository**
git clone https://github.com/yourusername/sentinel-edr.git
cd sentinel-edr

**2. Install dependencies**
pip install -r requirements.txt

**3. Configure API Keys**
Edit config/settings.json to insert your VirusTotal and Groq API keys:
* VirusTotal API: https://www.virustotal.com/
* Groq Console: https://console.groq.com/

{
  "general": {
    "scan_interval_seconds": 1.5,
    "log_file": "logs/edr_events.json"
  },
  "threat_intel": {
    "virustotal_api_key": "YOUR_VIRUSTOTAL_API_KEY",
    "vt_url": "https://www.virustotal.com/api/v3/files/",
    "malicious_threshold": 3,
    "cache_ttl_hours": 24
  },
  "ai_analyst": {
    "provider": "groq",
    "groq_api_key": "YOUR_GROQ_API_KEY",
    "model": "qwen/qwen3.8-27b"
  },
  "system_whitelist": [
    "system", "registry", "smss.exe", "csrss.exe", 
    "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe"
  ]
}

---

## 🛡️ Usage

**1. Launch the Sentinel EDR Console:**
Run the script inside an administrative terminal (required for PID termination and outbound firewall isolation):

python main.py

**2. Test Adversary Emulation:**
In a separate terminal, trigger the included test harness. This simulates an obfuscated PowerShell execution attempt without executing harmful operations:

python tests/malicious.py

Sentinel EDR will detect the behavioral anomaly, flag MITRE T1027, kill the process tree, and display the AI forensic briefing.

---

## 🎨 UI Architecture: Obsidian Vertex

The console interface utilizes a dark-mode command aesthetic engineered for clean operational visibility:
* **Targeting Reticle Canvas:** An animated radar canvas that draws a precision crosshair and rotating orbital tracker dot indicating live sweep status.
* **Wireframe Diamond AI Core:** A geometric vector canvas that pulses in sync with model generation and incident handling.
* **Color Palette:** Pure Pitch Black (`#000000`), Stark White (`#ffffff`), Emerald Green (`#10b981`), and Alert Crimson (`#ff0033`).

---

## ⚠️ Disclaimer
**For Educational, Research, and Demonstration Purposes Only.** 
Sentinel EDR is an experimental behavioral detection tool designed to showcase endpoint telemetry parsing, heuristic rules, and local triage automation. It does not replace commercial EDR/XDR platforms (such as CrowdStrike Falcon, SentinelOne, or Microsoft Defender for Endpoint) and should not be used as sole protection in enterprise production networks.