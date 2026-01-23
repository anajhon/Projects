import pandas as pd
import matplotlib.pyplot as plt
import re
import os
from io import BytesIO
import base64
import time

# *** CRITICAL FIX: FORCE HEADLESS BACKEND ***
# This tells Matplotlib not to rely on the Windows display server,
# ensuring it can create PNGs even when run in the background.
plt.switch_backend('Agg') 
# *******************************************

# --- ANSI COLOR CODES DEFINITIONS (COPIED FROM MAIN HONEYPOT) ---
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
BLINK = '\033[5m'
ENDC = '\033[0m' # Resets color and formatting
# -----------------------------------------------------------------

# --- Configuration ---
LOG_FILE = 'creds_audits.log'
REPORT_FILE = 'daily_threat_summary.html'
# IMPORTANT: This must match the format in your honeypot script's logging_format
LOG_COLUMNS = ['Level', 'Timestamp', 'Message']

def generate_report():
    print(f"Loading and processing log file: {LOG_FILE}...")

    # --- 1. Load and Process Data using Pandas ---
    try:
        # Read the entire file, using '|' as the separator (CRITICAL FIX)
        df = pd.read_csv(LOG_FILE, 
                         names=LOG_COLUMNS, 
                         sep='|', 
                         index_col=False, 
                         skipinitialspace=True,
                         engine='python',
                         on_bad_lines='skip',
                         header=None) 
        
        # Clean up columns read due to non-standard log formatting
        df[df.columns[0]] = df[df.columns[0]].astype(str).str.strip()
        df[df.columns[2]] = df[df.columns[2]].astype(str).str.strip()

    except Exception as e:
        print(f"{RED}Error reading log file: {e}{ENDC}")
        print("CRITICAL: Data read failed. Metrics will be 0.")
        return

    # *** FIX 1: Force the 'Message' column to string type ***
    df['Message'] = df['Message'].astype(str)
    # *******************************************************

    # --- 2. Feature Extraction ---
    
    # A. Extract IP address using Regular Expressions
    df['IP'] = df['Message'].str.extract(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    df['IP'] = df['IP'].fillna('N/A') 
    
    # B. Filter for command execution messages (Still needed for Total Connections calc)
    command_df = df[df['Message'].str.contains('Command executed by', na=False)].copy()
    
    # C. Filter for login failure messages
    failed_login_df = df[df['Message'].str.contains('Failed login attempt', na=False)]

    # --- 3. Analysis & Metrics ---
    
    # Metric 1: Total Connections (Established connections)
    total_connections = len(df[df['Message'].str.contains('Connection established')])
    
    # Metric 2: Total Failures
    total_failures = len(failed_login_df)
    
    # Metric 3: Top 5 Attacking IPs (Excluding 'N/A' and Internal IPs for clean charts)
    top_ips = df[~df['IP'].isin(['N/A', '127.0.0.1', '0.0.0.0', '::1'])]['IP'].value_counts().head(5)
    
    # --- 4. Visualization (Matplotlib) ---
    
    # Create figure and axes for the plots - Now only ONE chart axis is needed
    fig, ax = plt.subplots(figsize=(8, 6)) # Removed axes[1]
    fig.suptitle('CST8803 Honeypot Threat Intelligence Summary', fontsize=16, fontweight='bold')

    # Plot 1: Top 5 Attacking IPs (Using 'ax' instead of 'axes[0]')
    if not top_ips.empty:
        top_ips.plot(kind='barh', ax=ax, color='skyblue')
        ax.set_title('Top 5 Connecting IP Addresses')
        ax.set_xlabel('Total Attempts')
        ax.invert_yaxis()
    else:
        ax.text(0.5, 0.5, 'No External IP Data Captured', horizontalalignment='center', verticalalignment='center', transform=ax.transAxes, color='gray')
        ax.set_title('Top 5 Connecting IP Addresses')
        ax.set_xticks([])
        ax.set_yticks([])
        
    # --------------------------------------------------------------------------
    
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    
    # Save chart data to Base64 (needed for HTML embedding)
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_png = buffer.read()
    buffer.close()
    
    chart_base64 = base64.b64encode(image_png).decode('utf-8')
    
    # --- 5. Generate HTML Report ---
    
    # Get last 10 lines of the original log file for the snippet
    try:
        with open(LOG_FILE, 'r') as f:
            log_snippet = "".join(f.readlines()[-10:])
    except:
        log_snippet = "Could not read log snippet."

    html_content = f"""
    <html>
    <head>
        <title>Honeypot Threat Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .container {{ max-width: 1200px; margin: auto; }}
            .metric {{ padding: 15px; border-radius: 8px; margin-bottom: 20px; text-align: center; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
            .failure {{ background-color: #fcebeb; border-left: 5px solid red; }}
            .success {{ background-color: #e6ffe6; border-left: 5px solid green; }}
            h1 {{ border-bottom: 2px solid #ccc; padding-bottom: 10px; }}
            pre {{ background: #eee; padding: 15px; border-radius: 5px; white-space: pre-wrap; text-align: left; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>CST8803 Honeypot Threat Intelligence Summary</h1>
            <p>Report Date: <strong>{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}</strong></p>
            
            <div style="display: flex; justify-content: space-between; gap: 20px;">
                <div class="metric failure" style="flex: 1;">
                    <h2>Total Failed Logins</h2>
                    <p style="font-size: 2.5em; font-weight: bold; color: red;">{total_failures}</p>
                </div>
                <div class="metric success" style="flex: 1;">
                    <h2>Total Connections</h2>
                    <p style="font-size: 2.5em; font-weight: bold; color: green;">{total_connections}</p>
                </div>
            </div>

            <h2>Visual Attack Summary: Top Connecting IPs</h2>
            <div style="width: 65%; margin: auto;"> 
                <img src="data:image/png;base64,{chart_base64}" alt="Attack Charts" style="width: 100%;">
            </div>
            
            <h2>Raw Log Snippet (Last 10 Entries)</h2>
            <pre>{log_snippet}</pre>
        </div>
    </body>
    </html>
    """
    
    with open(REPORT_FILE, 'w') as f:
        f.write(html_content)
    
    print(f"\n{GREEN}{BOLD}Report Generated Successfully! Open {REPORT_FILE} in your browser for the demo.{ENDC}")

if __name__ == "__main__":
    generate_report()