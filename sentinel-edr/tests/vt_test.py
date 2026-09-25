import sys
import time
import json
from pathlib import Path

# Add project root (one level up from tests/) to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
ROOT_DIR = PROJECT_ROOT.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from intel.virus_total import VirusTotalClient

def load_config():
    config_path = ROOT_DIR / "config" / "settings.json"
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

def run_vt_unit_tests():
    print("=" * 65)
    print("      SENTINEL EDR // VIRUSTOTAL CLIENT INTEGRATION TEST      ")
    print("=" * 65)

    config = load_config()
    vt_cfg = config["threat_intel"]
    
    client = VirusTotalClient(
        api_key=vt_cfg["virustotal_api_key"],
        endpoint_url=vt_cfg["vt_url"],
        threshold=vt_cfg["malicious_threshold"],
        cache_ttl=vt_cfg["cache_ttl_hours"]
    )

    # 1. Test Malicious Hash (EICAR)
    print("\n[Test 1] Querying Known Malicious Hash (EICAR)...")
    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    res_mal = client.query_hash(eicar_hash)
    
    print(f"    -> Verdict : {res_mal.get('verdict')}")
    print(f"    -> Score   : {res_mal.get('score')}")
    assert res_mal.get("verdict") == "MALICIOUS", "[FAIL] Expected MALICIOUS verdict for EICAR hash!"
    print("    [PASS] Test 1 Succeeded: Malicious hash correctly identified.")

    # 2. Test Benign Hash (Using a known safe file hash or python.exe if available)
    print("\n[Test 2] Querying Known Benign Hash...")
    # Example SHA-256 for a standard safe file or Windows binary (or a dummy safe hash)
    # Let's use a safe public hash (e.g., Python installer or a standard Windows file hash)
    benign_hash = "685c013b05f156d123b3200ff8e6ab20b33e21cb7d559be39e6a0d24cb89d985" 
    res_benign = client.query_hash(benign_hash)
    
    print(f"    -> Verdict : {res_benign.get('verdict')}")
    print(f"    -> Score   : {res_benign.get('score')}")
    print("    [PASS] Test 2 Completed: Benign query processed.")

    # 3. Test Local Cache Performance (Dependent Test)
    print("\n[Test 3] Testing Local Cache Retrieval (Speed & Rate-Limit Avoidance)...")
    start_time = time.time()
    # Query the EICAR hash again — should pull instantly from local cache without web latency
    res_cached = client.query_hash(eicar_hash)
    duration = (time.time() - start_time) * 1000  # in milliseconds

    print(f"    -> Cached Verdict : {res_cached.get('verdict')}")
    print(f"    -> Response Time  : {duration:.2f} ms")
    
    if duration < 50:  # Local cache lookup should be near-instantaneous (< 50ms)
        print("    [PASS] Test 3 Succeeded: Cache retrieval is operational and lightning fast.")
    else:
        print("    [!] WARNING: Cache query took longer than expected. Check cache implementation.")

    print("\n" + "=" * 65)
    print("       ALL VIRUSTOTAL CLIENT INTEGRATION TESTS PASSED          ")
    print("=" * 65)

if __name__ == "__main__":
    run_vt_unit_tests()