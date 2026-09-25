import subprocess
import logging

class FirewallIsolation:
    @staticmethod
    def block_remote_ip(ip_address: str) -> bool:
        """
        Dynamically blocks outbound traffic to a malicious C2 IP address 
        using Windows Advanced Firewall.
        """
        if not ip_address or ip_address == "N/A":
            return False

        # Create a unique, clean rule name
        rule_name = f"EDR_AUTO_BLOCK_{ip_address.replace('.', '_')}"
        
        # Construct the netsh command as an argument list (prevents shell injection vulnerabilities)
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"remoteip={ip_address}"
        ]

        try:
            # Execute the command and capture output
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=True
            )
            logging.info(f"[FIREWALL] Successfully blocked C2 IP {ip_address}. Output: {result.stdout.strip()}")
            print(f"    [+] ACTIVE RESPONSE: Firewall rule created. Outbound traffic to {ip_address} is BLOCKED.")
            return True

        except subprocess.CalledProcessError as e:
            # Fired if netsh fails (e.g., script is not running as Administrator)
            error_msg = e.stderr.strip() if e.stderr else "Unknown error"
            logging.error(f"[FIREWALL] Failed to block IP {ip_address}. Error: {error_msg}")
            print(f"    [X] Firewall Isolation Failed (Are you running as Administrator?): {error_msg}")
            return False

        except Exception as e:
            logging.error(f"[FIREWALL] Unexpected exception during firewall isolation: {str(e)}")
            return False

    @staticmethod
    def remove_block_rule(ip_address: str) -> bool:
        """Rollback utility for analysts to remove the isolation rule after remediation."""
        rule_name = f"EDR_AUTO_BLOCK_{ip_address.replace('.', '_')}"
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"    [-] Rolled back firewall block for IP {ip_address}.")
            return True
        except subprocess.CalledProcessError:
            return False