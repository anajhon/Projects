import logging
import socket
import threading
import paramiko
from logging.handlers import RotatingFileHandler
import time
import os
import sys
# --- EMAIL RELATED IMPORTS ---
import smtplib
from email.message import EmailMessage
# -----------------------------

# --- ANSI COLOR CODES FOR ALERTS ---
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
BLINK = '\033[5m'
ENDC = '\033[0m' # Resets color and formatting
# -----------------------------------

# --- CONFIGURATION (GMAIL SENDER - CORRECTED) ---
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587 # Port standard for STARTTLS

SENDER_EMAIL = 'soukff346@gmail.com'
SENDER_PASSWORD = 'xceudovvqzpidxmt' # The App Password
RECEIVER_EMAIL = 'Anas-elmouhtadi@outlook.com'
# ---------------------------------------------

# Constants
# *** CRITICAL FIX: STRUCTURED LOG FORMAT FOR ANALYSIS SCRIPT ***
logging_format = logging.Formatter('%(levelname)s|%(asctime)s|%(message)s') 
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"
host_key = paramiko.RSAKey(filename="server.key")

# Unified Logger setup (Global instance)
creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
log_file_path = "creds_audits.log"
creds_handler = RotatingFileHandler(log_file_path, maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

# --- GEOIP LOOKUP FUNCTION (STATIC INTERNAL CHECK) ---
def get_ip_info(ip):
    """Returns static 'Internal Network' location for stable local testing."""
    if ip in ['127.0.0.1', '0.0.0.0'] or ip.startswith(('192.168.', '10.', '172.16')):
        return "Internal Network (Simulated)"
    return "External Access Attempt" # Placeholder for non-internal IPs


# --- HTML TEMPLATING FUNCTION (CVSS INTEGRATED) ---
def create_html_body(event_type, ip, location, details, cvss_score=None, severity=None):
    """Generates an HTML body for a security alert, including CVSS scoring."""
    
    color = "red" if "FAILED" in event_type or "CRITICAL" in event_type else "#4CAF50"
    
    # Generate CVSS row if scores are provided
    cvss_row = ""
    if cvss_score and severity:
        cvss_color = "red" if cvss_score >= 8.6 else ("orange" if cvss_score >= 4.0 else "#4CAF50")
        cvss_row = f"""
        <tr>
            <td style="background-color: #fdd; font-weight: bold; color: {cvss_color};">CVSS Score (Sim.):</td>
            <td style="background-color: #fff; color: {cvss_color};"><strong>{severity} ({cvss_score})</strong></td>
        </tr>
        """
    
    # HTML structure using inline CSS for presentation
    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6;">
        <div style="border: 2px solid {color}; padding: 15px; border-radius: 5px; background-color: #f9f9f9;">
            <h2 style="color: {color}; margin-top: 0;">&#9888; {event_type} ALERT!</h2>
            <p>A suspicious activity was detected by the Honeypot:</p>
            <table border="0" cellpadding="8" cellspacing="0" style="width: 100%; border-collapse: collapse;">
                {cvss_row}
                <tr>
                    <td style="background-color: #eee; font-weight: bold; width: 30%;">IP Address:</td>
                    <td style="background-color: #fff;">{ip}</td>
                </tr>
                <tr>
                    <td style="background-color: #eee; font-weight: bold;">Location:</td>
                    <td style="background-color: #fff;">{location}</td>
                </tr>
                {details}
                <tr>
                    <td style="background-color: #eee; font-weight: bold;">Time:</td>
                    <td style="background-color: #fff;">{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}</td>
                </tr>
            </table>
            <p style="margin-top: 20px; color: #555;">Review the 'creds_audits.log' for full session details.</p>
        </div>
    </body>
    </html>
    """
    return html_content


# --- EMAIL ALERT FUNCTION (MODIFIED FOR HTML) ---
def send_alert_email(subject, html_body):
    msg = EmailMessage()
    msg['Subject'] = f'[HONEYPOT ALERT] {subject}'
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL
    
    msg.set_content("A critical alert was triggered by the honeypot. Please check your email client for the HTML version of this alert.")
    
    msg.add_alternative(html_body, subtype='html')

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        print(f"{RED}{BOLD}[!!! EMAIL FAILED !!!] Could not send alert: {e}{ENDC}\n")


# --- CORE HONEYPOT FUNCTIONS ---

def get_ls_output():
    files_and_dirs = [
        ("jumpbox1.conf", "rw-r--r--", "1K", "2022-08-05 14:32"),
        ("file1.txt", "rw-r--r--", "1.2M", "2023-02-20 08:14"),
        ("file2.txt", "rw-r--r--", "234K", "2023-04-17 12:56"),
        (".bashrc", "rw-------", "1.5K", "2021-11-11 10:45"),
        (".gitignore", "rw-r--r--", "3.5K", "2022-01-09 09:30"),
        ("directory1", "drwxr-xr-x", "-", "2022-07-25 16:22"),
        ("directory2", "drwxr-xr-x", "-", "2023-01-15 13:05"),
        ("subdir1", "drwxr-xr-x", "-", "2023-04-01 16:11"),
    ]
    
    output = ""
    for item, perms, size, timestamp in files_and_dirs:
        formatted_line = f"{perms:<12} 1 root root {size:>6} {timestamp:<19} {item}"
        output += formatted_line + "\r\n" 
    
    return output.encode()

def emulated_shell(channel, client_ip, username, password):
    # Prompt is defined here and used to determine backspace boundary
    PROMPT_TEXT = b"corporate-jumpbox2$"
    
    # We send the prompt and set the initial command buffer to empty
    channel.send(PROMPT_TEXT) 
    command = b''
    
    connection_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    creds_logger.info(f"Connection established from {client_ip} with username: {username} and password: {password} at {connection_time}")

    while True:
        try:
            char = channel.recv(1)
        except EOFError: 
            print(f"Client {client_ip} disconnected.")
            break

        if not char: 
            channel.close()
            break

        # --- FIX: Prevent backspace from erasing the prompt ---
        if char == b'\x08' or char == b'\x7f':
            if len(command) > 0:
                command = command[:-1]
                # Send sequence to erase character: move cursor back, print space, move cursor back again
                channel.send(b'\x08 \x08')
            continue
        # ----------------------------------------------------

        if char == b'\r':
            channel.send(b'\r\n') 
            command_str = command.strip().decode('utf-8', errors='ignore')
            
            if command_str: 
                # LOGGING CHANGE: Use structured format for analysis tool
                creds_logger.info(f"Command executed by {client_ip}: {command_str}")

            response = b""
            
            # --- Command Handling Logic ---
            if command_str == "exit":
                # FIX: Shut down the entire Python interpreter process
                response = b"Honeypot shutting down...\r\n"
                channel.send(response)
                os._exit(0) 
                break 
            
            # Reconnaissance: OS Fingerprinting (3.0 LOW)
            elif command_str == 'uname -a':
                print(f"\n{YELLOW}{BOLD}[!!! WARNING CMD - CVSS 3.0 !!!] {client_ip} ran 'uname -a' (OS Fingerprinting){ENDC}\n")
                details = f"""<tr><td style="background-color: #eee; font-weight: bold;">Command Context:</td><td style="background-color: #fff;">{command_str} - OS Fingerprinting</td></tr>"""
                html_body = create_html_body("WARNING COMMAND", client_ip, username, details, cvss_score=3.0, severity="LOW")
                threading.Thread(target=send_alert_email, args=("WARNING CMD: uname -a", html_body)).start()
                response = b"Linux corporate-jumpbox2 5.15.0-78-generic #85-Ubuntu SMP Wed Jul 12 11:22:42 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n"

            # Reconnaissance: Local Network Mapping (3.0 LOW)
            elif command_str == 'ip a':
                print(f"\n{YELLOW}{BOLD}[!!! WARNING CMD - CVSS 3.0 !!!] {client_ip} ran 'ip a' (Local Network Mapping){ENDC}\n")
                details = f"""<tr><td style="background-color: #eee; font-weight: bold;">Command Context:</td><td style="background-color: #fff;">{command_str} - Local Network Mapping</td></tr>"""
                html_body = create_html_body("WARNING COMMAND", client_ip, username, details, cvss_score=3.0, severity="LOW")
                threading.Thread(target=send_alert_email, args=("WARNING CMD: ip a", html_body)).start()
                response = (
                    b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\r\n"
                    b"    inet 127.0.0.1/8 scope host lo\r\n"
                    b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\r\n"
                    b"    inet 10.10.2.5/24 brd 10.10.2.255 scope global eth0\r\n"
                )

            # Reconnaissance: Port/Service Mapping (4.0 MEDIUM)
            elif command_str == 'netstat -tuln':
                print(f"\n{YELLOW}{BOLD}[!!! WARNING CMD - CVSS 4.0 !!!] {client_ip} ran 'netstat -tuln' (Network Reconnaissance){ENDC}\n")
                details = f"""<tr><td style="background-color: #eee; font-weight: bold;">Command Context:</td><td style="background-color: #fff;">{command_str} - Network Reconnaissance</td></tr>"""
                html_body = create_html_body("WARNING COMMAND", client_ip, username, details, cvss_score=4.0, severity="MEDIUM")
                threading.Thread(target=send_alert_email, args=("WARNING CMD: netstat", html_body)).start()
                response = (
                    b"Active Internet connections (only servers)\r\n"
                    b"Proto Recv-Q Send-Q Local Address           Foreign Address         State      \r\n"
                    b"tcp        0      0 0.0.0.0:2223            0.0.0.0:* LISTEN     \r\n"
                    b"tcp        0      0 127.0.0.1:25            0.0.0.0:* LISTEN     \r\n\r\n"
                )
            
            # Reconnaissance: Privilege Check (ID) (3.5 LOW)
            elif command_str == 'id':
                print(f"\n{YELLOW}{BOLD}[!!! WARNING CMD - CVSS 3.5 !!!] {client_ip} ran 'id' (Privilege Check){ENDC}\n")
                details = f"""<tr><td style="background-color: #eee; font-weight: bold;">Command Context:</td><td style="background-color: #fff;">{command_str} - Privilege Check</td></tr>"""
                html_body = create_html_body("WARNING COMMAND", client_ip, username, details, cvss_score=3.5, severity="LOW")
                threading.Thread(target=send_alert_email, args=("WARNING CMD: id", html_body)).start()
                response = b"uid=1000(corpuser1) gid=1000(corpuser1) groups=1000(corpuser1),4(adm),24(cdrom),27(sudo),30(dip)\r\n"

            # Reconnaissance: Privilege Check (SUDO) (4.5 MEDIUM)
            elif command_str == 'sudo -l':
                print(f"\n{YELLOW}{BOLD}[!!! WARNING CMD - CVSS 4.5 !!!] {client_ip} ran 'sudo -l' (Escalation Attempt){ENDC}\n")
                details = f"""<tr><td style="background-color: #eee; font-weight: bold;">Command Context:</td><td style="background-color: #fff;">{command_str} - Privilege Escalation Check</td></tr>"""
                html_body = create_html_body("WARNING COMMAND", client_ip, username, details, cvss_score=4.5, severity="MEDIUM")
                threading.Thread(target=send_alert_email, args=("WARNING CMD: sudo -l", html_body)).start()
                response = b"User corpuser1 may run the following commands on corporate-jumpbox2:\r\n    (ALL) ALL\r\n"

            # Reconnaissance: History Check (3.0 LOW)
            elif command_str == 'history':
                print(f"\n{YELLOW}{BOLD}[!!! WARNING CMD - CVSS 3.0 !!!] {client_ip} ran 'history' (Activity Check){ENDC}\n")
                details = f"""<tr><td style="background-color: #eee; font-weight: bold;">Command Context:</td><td style="background-color: #fff;">{command_str} - User Activity Reconnaissance</td></tr>"""
                html_body = create_html_body("WARNING COMMAND", client_ip, username, details, cvss_score=3.0, severity="LOW")
                threading.Thread(target=send_alert_email, args=("WARNING CMD: history", html_body)).start()
                response = b" 1001  ls -la\r\n 1002  pwd\r\n 1003  whoami\r\n 1004  sudo -l\r\n"

            # CRITICAL: Credential File Access (9.9 CRITICAL)
            elif command_str == 'cat /etc/passwd':
                print(f"\n{RED}{BOLD}[!!! CRITICAL CMD - CVSS 9.9 !!!] {client_ip} ran 'cat /etc/passwd' (Credential Exposure){ENDC}\n")
                details = f"""<tr><td style="background-color: #eee; font-weight: bold;">Command Context:</td><td style="background-color: #fff;">{command_str} - Credential Exposure Attempt</td></tr>"""
                html_body = create_html_body("CRITICAL COMMAND", client_ip, username, details, cvss_score=9.9, severity="CRITICAL")
                threading.Thread(target=send_alert_email, args=("CRITICAL CMD: cat /etc/passwd", html_body)).start()
                response = b"root:x:0:0:root:/root:/bin/bash\r\ncorpuser1:x:1000:1000:,,,:/home/corpuser1:/bin/bash\r\n"

            # CRITICAL: Data Exfiltration (9.8 CRITICAL)
            elif command_str == 'cat jumpbox1.conf':
                print(f"\n{RED}{BOLD}[!!! CRITICAL CMD - CVSS 9.8 !!!] {client_ip} ran 'cat jumpbox1.conf' (Data Exposure Attempt){ENDC}\n")
                details = f"""<tr><td style="background-color: #eee; font-weight: bold;">Command Context:</td><td style="background-color: #fff;">{command_str} - Data Exfiltration Attempt</td></tr>"""
                html_body = create_html_body("CRITICAL COMMAND", client_ip, username, details, cvss_score=9.8, severity="CRITICAL")
                threading.Thread(target=send_alert_email, args=("CRITICAL CMD: cat jumpbox1.conf", html_body)).start()
                response = (
                    b"// Internal Configuration File - DO NOT ACCESS\r\n"
                    b"Database_IP=10.10.10.5\r\n"
                    b"Secret_Key=QWERT-YUIOP-ASDFG-HJKL\r\n\r\n"
                )
            
            # CRITICAL: Availability Attack (8.6 HIGH)
            elif command_str == 'shutdown':
                print(f"\n{RED}{BLINK}{BOLD}[!!! SHUTDOWN - CVSS 8.6 !!!] {client_ip} ran 'shutdown'!{ENDC}\n")
                details = f"""<tr><td style="background-color: #eee; font-weight: bold;">Command Context:</td><td style="background-color: #fff;">{command_str} - Availability Attack</td></tr>"""
                html_body = create_html_body("CRITICAL COMMAND", client_ip, username, details, cvss_score=8.6, severity="HIGH")
                threading.Thread(target=send_alert_email, args=("CRITICAL CMD: shutdown", html_body)).start()
                response = b"Shutting down the server...\r\n"
                channel.send(response)
                os._exit(0)
                break

            # WARNING: Integrity Impact (7.5 HIGH)
            elif command_str.startswith('delete '):
                print(f"\n{RED}{BOLD}[!!! WARNING CMD - CVSS 7.5 !!!] {client_ip} ran 'delete' (Integrity Impact){ENDC}\n")
                filename = command_str.split(' ', 1)[1]
                details = f"""<tr><td style="background-color: #eee; font-weight: bold;">Command Context:</td><td style="background-color: #fff;">{command_str} - Integrity Impact</td></tr>"""
                html_body = create_html_body("WARNING COMMAND", client_ip, username, details, cvss_score=7.5, severity="HIGH")
                threading.Thread(target=send_alert_email, args=(f"WARNING CMD: delete {filename}", html_body)).start()

                parts = command_str.split(' ', 1)
                if len(parts) == 2:
                    response = f"Simulated file deletion: {filename}\r\n".encode()
                    creds_logger.info(f"Simulated file deletion by {client_ip}: {filename}")
                else:
                    response = b"Error: Please provide a filename to delete.\r\n"
            
            # --- DEFAULT COMMANDS ---
            elif command_str == 'ps':
                response = (
                    b" PID TTY          TIME CMD\r\n"
                    b"   1 ?        00:00:01 init\r\n"
                    b" 105 ?        00:00:00 sshd: corpuser1@pts/0\r\n"
                    b" 106 pts/0    00:00:00 bash\r\n\r\n"
                )
            elif command_str == 'restart':
                response = b"Restarting the server...\r\n"
                channel.send(response)
                os.execl(sys.executable, sys.executable, *sys.argv)
                break
            elif command_str == "exit":
                # FIX: Shut down the entire Python interpreter process
                response = b"Honeypot shutting down...\r\n"
                channel.send(response)
                os._exit(0) 
                break 
            elif command_str == 'pwd':
                response = b"/usr/local\r\n"
            elif command_str == 'whoami':
                response = b"corpuser1\r\n"
            elif command_str == 'ls':
                response = get_ls_output() 
            # ------------------------
            else:
                response = b"Command not found\r\n"

            # --- Final Sequence ---
            channel.send(response)
            channel.send(PROMPT_TEXT) # Use PROMPT_TEXT here
            command = b''
            
        else:
            channel.send(char)
            command += char

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None, location=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password
        self.location = location # Stored location data

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auth(self):
        return "password"

    def check_auth_password(self, username, password):
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        if username == self.input_username and password == self.input_password:
            # --- CONSOLE ALERT ON SUCCESSFUL LOGIN ---
            print(f"\n{GREEN}{BOLD}>>>> AUTH SUCCESS! <<<< User: {username} from {self.client_ip} [{self.location}]{ENDC}\n")
            
            # Email Alert (Adding location to body)
            details = f"""
            <tr>
                <td style="background-color: #eee; font-weight: bold;">Username:</td>
                <td style="background-color: #fff;">{username}</td>
            </tr>
            <tr>
                <td style="background-color: #eee; font-weight: bold;">Password:</td>
                <td style="background-color: #fff;">{password}</td>
            </tr>
            """
            html_body = create_html_body("SUCCESSFUL LOGIN", self.client_ip, self.location, details)
            threading.Thread(target=send_alert_email, args=("SUCCESSFUL LOGIN", html_body)).start()

            creds_logger.info(f"Successful login from {self.client_ip} with username: {username} and password: {password} at {current_time}")
            return paramiko.AUTH_SUCCESSFUL
        else:
            # --- CONSOLE ALERT ON FAILED LOGIN ---
            print(f"\n{RED}{BOLD}>>>> AUTH FAILED! <<<< IP: {self.client_ip} [{self.location}], Attempted User: {username}, Pass: {password}{ENDC}\n")
            
            # Email Alert (Adding location to body)
            details = f"""
            <tr>
                <td style="background-color: #eee; font-weight: bold; color: red;">Attempted Username:</td>
                <td style="background-color: #fff; color: red;">{username}</td>
            </tr>
            <tr>
                <td style="background-color: #eee; font-weight: bold; color: red;">Attempted Password:</td>
                <td style="background-color: #fff; color: red;">{password}</td>
            </tr>
            """
            html_body = create_html_body("FAILED LOGIN ATTEMPT", self.client_ip, self.location, details)
            threading.Thread(target=send_alert_email, args=("FAILED LOGIN ATTEMPT", html_body)).start()

            creds_logger.warning(f"Failed login attempt from {self.client_ip} with username: {username} and password: {password} at {current_time}")
            return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        # Log terminal forensic data
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        client_ip = self.client_ip
        creds_logger.info(f"Terminal Info from {client_ip}: Type={term}, Size={width}x{height} (Cols x Rows) at {current_time}")
        return True

    def check_channel_exec_request(self, channel, command):
        command_str = command.decode('utf-8', errors='ignore')
        creds_logger.info(f"Exec request from {self.client_ip}: {command_str}")
        return True

def client_handler(client, addr, username, password):
    client_ip = addr[0]
    # 1. Get GeoIP Location (STATIC internal check)
    location = get_ip_info(client_ip) 
    
    print(f"{CYAN}Connection established from {client_ip} [{location}]{ENDC}")
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        # 2. Pass location to Server class
        server = Server(client_ip=client_ip, input_password=password, input_username=username, location=location) 
        transport.add_server_key(host_key)
        transport.start_server(server=server)
        
        channel = transport.accept(20)
        
        if channel is None:
            print(f"No channel was opened by {client_ip}.")
            if transport.is_active():
                creds_logger.info(f"Connection from {client_ip} closed after no channel opened.")
            client.close()
            return

        print(f"Channel opened successfully for {client_ip}.")
        standard_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n" 
        channel.send(standard_banner.encode())

        emulated_shell(channel, client_ip=client_ip, username=username, password=password)

    except paramiko.SSHException as ssh_err:
        creds_logger.error(f"SSH error with client {client_ip}: {str(ssh_err)}")
        print(f"SSH error with client {client_ip}: {str(ssh_err)}")
    except Exception as error:
        creds_logger.error(f"General error with client {client_ip}: {str(error)}")
        print(f"General error with client {client_ip}: {str(error)}")
    finally:
        if client:
            client.close()
        print(f"{CYAN}Connection from {client_ip} closed.{ENDC}")


def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        socks.bind((address, int(port)))
    except Exception as e:
        print(f"Error binding to {address}:{port} - {str(e)}")
        creds_logger.error(f"Error binding to {address}:{port} - {str(e)}")
        return

    socks.listen(100)
    print(f"SSH server is listening on {address}:{port}.")
    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handler, args=(client, addr, username, password))
            ssh_honeypot_thread.start()
        except Exception as error:
            creds_logger.error(f"Error accepting client connection: {str(error)}")
            print(f"Error accepting client connection: {str(error)}")

if __name__ == "__main__":
    if not os.path.exists("server.key"):
        print("server.key not found. Generating a new RSA key pair...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file("server.key")
        print("server.key generated.")
        host_key = key
    else:
        print("Using existing server.key.")
    
    HONEYPOT_ADDRESS = "0.0.0.0"
    HONEYPOT_PORT = 2223
    VALID_USERNAME = "username"
    VALID_PASSWORD = "password"

    print(f"{CYAN}Starting honeypot on {HONEYPOT_ADDRESS}:{HONEYPOT_PORT}. Alerts sent to {RECEIVER_EMAIL}{ENDC}")
    honeypot(HONEYPOT_ADDRESS, HONEYPOT_PORT, VALID_USERNAME, VALID_PASSWORD)