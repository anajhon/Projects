import sys
import time
import socket
import json
import subprocess
from pathlib import Path

# Add project root (one level up from tests/) to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
ROOT_DIR = PROJECT_ROOT.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from intel.virus_total import VirusTotalClient

def load_config():
    # Handle path resolution whether running as raw script or compiled PyInstaller .exe
    if getattr(sys, 'frozen', False):
        base_path = Path(sys._MEIPASS)
    else:
        base_path = ROOT_DIR
        
    config_path = base_path / "config" / "settings.json"
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

def test_virustotal_eicar_scan():
    print("\n[*] Stage 1: Testing VirusTotal Cloud Threat Intelligence (EICAR Hash)...")
    
    config = load_config()
    vt_cfg = config["threat_intel"]
    vt_client = VirusTotalClient(
        api_key=vt_cfg["virustotal_api_key"],
        endpoint_url=vt_cfg["vt_url"],
        threshold=vt_cfg["malicious_threshold"],
        cache_ttl=vt_cfg["cache_ttl_hours"]
    )
    
    # Universal EICAR Test File SHA-256 hash (Guaranteed MALICIOUS verdict on VT)
    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    print(f"    [-] Querying VirusTotal for hash: {eicar_hash}")
    
    result = vt_client.query_hash(eicar_hash)
    verdict = result.get("verdict", "UNKNOWN")
    score = result.get("score", 0)
    
    print(f"    [+] VT Verdict   : {verdict}")
    print(f"    [+] Threat Score : {score} / {vt_cfg['malicious_threshold']}")
    
    if verdict == "MALICIOUS":
        print("    [+] SUCCESS: VirusTotal successfully returned a MALICIOUS verdict!")
    else:
        print("    [-] WARNING: Received Benign or cache miss. Verify your API key.")

def simulate_obfuscated_powershell():
    print("\n[*] Stage 2: Spawning obfuscated PowerShell stager (MITRE T1027 - Behavioral Test)...")
    cmd = [
        "powershell.exe",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-Command",
        "Write-Host '[MALWARE] Stager active in background. Beaconing...'; Start-Sleep -Seconds 30"
    ]
    
    try:
        proc = subprocess.Popen(
            cmd,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
        )
        print(f"    [+] Malicious PowerShell process spawned with PID: {proc.pid}")
        print("    [+] Waiting for Mini-EDR agent (main.py) to intercept and kill it...")
        
        for elapsed in range(1, 16):
            if proc.poll() is not None:
                print(f"\n[+] SUCCESS: Mini-EDR successfully intercepted and KILLED PID {proc.pid}!")
                return True
            time.sleep(1)
            print(f"    ... monitoring target ({elapsed}s)", end="\r")
            
        print("\n[!] Process survived 15s timeout. Terminating manually.")
        proc.terminate()
        return False
        
    except Exception as e:
        print(f"[-] Failed to launch simulation process: {e}")
        return False

def simulate_c2_socket_connection():
    print("\n[*] Stage 3: Simulating Command & Control (C2) Egress Connection...")
    c2_ip = "198.51.100.42"
    c2_port = 4443
    
    print(f"    [-] Attempting TCP connection to mock C2 server at {c2_ip}:{c2_port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((c2_ip, c2_port))
    except socket.timeout:
        print("    [+] Socket connection timed out as expected (Non-routable C2 destination).")
    except Exception as e:
        print(f"    [+] Network interaction completed: {e}")
    finally:
        s.close()

def main():
    print("=" * 65)
    print("       SENTINEL EDR // COMPREHENSIVE ADVERSARY SIMULATION       ")
    print("=" * 65)
    
    test_virustotal_eicar_scan()
    simulate_obfuscated_powershell()
    simulate_c2_socket_connection()

    print("\n" + "=" * 65)
    print("         SIMULATION COMPLETED - CHECK EDR GUI & DOSSIER         ")
    print("=" * 65)

if __name__ == "__main__":
    main()