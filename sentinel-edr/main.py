import os
import sys
import time
import json
import math
import queue
import logging
import hashlib
import threading
from pathlib import Path
from datetime import datetime
import psutil
import requests
import customtkinter as ctk

# Resolve internal EDR modules
from rules.heuristics import BehavioralRuleEngine
from intel.virus_total import VirusTotalClient  # type: ignore

try:
    from core.containment import ContainmentEngine, FirewallIsolation  # type: ignore
except ImportError:
    from containment import ContainmentEngine  # type: ignore
    from firewall import FirewallIsolation  # type: ignore

# Configure Theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -------------------------------------------------------------
# 1. OBSIDIAN VERTEX: TARGETING RETICLE CANVAS
# -------------------------------------------------------------
class TargetingReticleCanvas(ctk.CTkCanvas):
    def __init__(self, parent, size=160, **kwargs):
        # True pitch black background
        super().__init__(parent, width=size, height=size, bg="#000000", highlightthickness=0, **kwargs)
        self.size = size
        self.center = size // 2
        self.radius = (size // 2) - 20
        self.state = "PATROLLING"
        self.angle = 0
        self.pulse = 0
        self.pulse_dir = 1
        self._is_running = True
        self.after(30, self._animate)

    def set_state(self, state: str):
        self.state = state

    def _animate(self):
        if not self._is_running:
            return

        self.delete("all")
        c = self.center
        r = self.radius

        # Obsidian Vertex Palette: Stark White, Emerald Green, and alert Crimson
        if self.state == "PATROLLING":
            accent = "#10b981"  # Emerald Green
        elif self.state == "INSPECTING":
            accent = "#ffffff"  # Stark White
        elif self.state == "CONTAINING":
            accent = "#ff0033"  # Crimson Alert
        else:
            accent = "#10b981"

        # Static Monochromatic Crosshairs
        self.create_line(c, c - r - 10, c, c + r + 10, fill="#222222", width=1)
        self.create_line(c - r - 10, c, c + r + 10, c, fill="#222222", width=1)
        
        # Outer Circular Edge
        self.create_oval(c - r, c - r, c + r, c + r, outline="#1a1a1a", width=2)
        
        # Inner bounds
        self.create_oval(c - r + 8, c - r + 8, c + r - 8, c + r - 8, outline="#111111", width=1)

        # Rotating Tracking Dot
        self.angle = (self.angle + 3) % 360
        rad = math.radians(self.angle)
        dot_x = c + r * math.cos(rad)
        dot_y = c + r * math.sin(rad)
        
        self.create_oval(dot_x - 4, dot_y - 4, dot_x + 4, dot_y + 4, fill=accent, outline="")
        
        # Center Point
        self.create_oval(c - 2, c - 2, c + 2, c + 2, fill="#ffffff", outline="")

        # Alert state visual
        if self.state == "CONTAINING":
            self.pulse += 1 * self.pulse_dir
            if self.pulse >= 10 or self.pulse <= 0:
                self.pulse_dir *= -1
            self.create_oval(c - r - self.pulse, c - r - self.pulse, c + r + self.pulse, c + r + self.pulse, outline="#ff0033", width=1)

        self.after(30, self._animate)

# -------------------------------------------------------------
# 2. OBSIDIAN VERTEX: WIREFRAME DIAMOND AI CANVAS
# -------------------------------------------------------------
class WireframeDiamondCanvas(ctk.CTkCanvas):
    def __init__(self, parent, size=120, **kwargs):
        super().__init__(parent, width=size, height=size, bg="#000000", highlightthickness=0, **kwargs)
        self.size = size
        self.center = size // 2
        self.pulse = 0
        self.pulse_dir = 1
        self._is_running = True
        self.after(40, self._animate_node)

    def _animate_node(self):
        if not self._is_running:
            return

        self.delete("all")
        c = self.center

        # Slow, cold logical pulse
        self.pulse += 0.15 * self.pulse_dir
        if self.pulse >= 3 or self.pulse <= 0:
            self.pulse_dir *= -1

        r_outer = 40
        r_inner = 25

        # Outer Emerald Diamond
        points_outer = [
            (c, c - r_outer),
            (c + r_outer, c),
            (c, c + r_outer),
            (c - r_outer, c)
        ]
        self.create_polygon(points_outer, outline="#10b981", fill="", width=1 + self.pulse)

        # Inner White Diamond
        points_inner = [
            (c, c - r_inner),
            (c + r_inner, c),
            (c, c + r_inner),
            (c - r_inner, c)
        ]
        self.create_polygon(points_inner, outline="#ffffff", fill="", width=1)

        # Intersecting logical lines
        self.create_line(c, c - r_outer, c, c + r_outer, fill="#10b981", width=1)
        self.create_line(c - r_outer, c, c + r_outer, c, fill="#10b981", width=1)

        self.after(40, self._animate_node)

# -------------------------------------------------------------
# 3. MAIN EDR UI WINDOW (OBSIDIAN VERTEX)
# -------------------------------------------------------------
class UnifiedSentinelApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SENTINEL-EDR // Obsidian Vertex Command")
        self.geometry("1400x780")
        self.minsize(1200, 680)
        # Pitch black background
        self.configure(fg_color="#000000")

        self.event_queue = queue.Queue()
        self.is_running = True
        self.last_event = None

        self._build_ui()
        self._start_edr_background_worker()
        self._process_queue()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=0, minsize=310)
        self.grid_columnconfigure(1, weight=1, minsize=420)
        self.grid_columnconfigure(2, weight=1, minsize=420)
        self.grid_rowconfigure(0, weight=1)

        # -----------------------------------------------------
        # COLUMN 0: LEFT PANEL (Avatar & Agent Status)
        # -----------------------------------------------------
        # Stark borders, zero corner radius
        left_panel = ctk.CTkFrame(self, fg_color="#000000", corner_radius=0, border_width=1, border_color="#222222")
        left_panel.grid(row=0, column=0, padx=(15, 8), pady=15, sticky="nsew")

        lbl_title = ctk.CTkLabel(left_panel, text="SENTINEL EDR", font=ctk.CTkFont(family="Consolas", size=22, weight="bold"), text_color="#ffffff")
        lbl_title.pack(pady=(25, 2))
        lbl_sub = ctk.CTkLabel(left_panel, text="OBSIDIAN VERTEX // ACTIVE", font=ctk.CTkFont(family="Consolas", size=10), text_color="#10b981")
        lbl_sub.pack(pady=(0, 20))

        # Avatar Container
        face_box = ctk.CTkFrame(left_panel, fg_color="#000000", corner_radius=0, border_width=1, border_color="#1a1a1a")
        face_box.pack(padx=18, pady=8, fill="x")

        self.agent_face = TargetingReticleCanvas(face_box, size=160)
        self.agent_face.pack(pady=15)

        self.lbl_status = ctk.CTkLabel(face_box, text="STATUS: PATROLLING", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), text_color="#10b981")
        self.lbl_status.pack(pady=(0, 15))

        # Specs
        specs_box = ctk.CTkFrame(left_panel, fg_color="#000000", corner_radius=0, border_width=1, border_color="#1a1a1a")
        specs_box.pack(padx=18, pady=10, fill="x")

        ctk.CTkLabel(specs_box, text="SYS.BEHAVIORAL : ACTIVE", font=ctk.CTkFont(family="Consolas", size=11), text_color="#aaaaaa", anchor="w").pack(padx=15, pady=(12, 4), fill="x")
        ctk.CTkLabel(specs_box, text="SYS.FIREWALL   : READY", font=ctk.CTkFont(family="Consolas", size=11), text_color="#aaaaaa", anchor="w").pack(padx=15, pady=4, fill="x")
        ctk.CTkLabel(specs_box, text="NET.INTEL      : ONLINE", font=ctk.CTkFont(family="Consolas", size=11), text_color="#aaaaaa", anchor="w").pack(padx=15, pady=4, fill="x")
        ctk.CTkLabel(specs_box, text="AI.ANALYST     : READY", font=ctk.CTkFont(family="Consolas", size=11), text_color="#10b981", anchor="w").pack(padx=15, pady=(4, 12), fill="x")

        # Counters
        stat_frame = ctk.CTkFrame(left_panel, fg_color="transparent")
        stat_frame.pack(padx=18, pady=10, fill="x")
        stat_frame.grid_columnconfigure(0, weight=1)
        stat_frame.grid_columnconfigure(1, weight=1)

        self.stat_threats = self._create_stat_badge(stat_frame, "NEUTRALIZED", "0", "#ffffff", 0)
        self.stat_resumed = self._create_stat_badge(stat_frame, "VERIFIED", "0", "#10b981", 1)

        # -----------------------------------------------------
        # COLUMN 1: MIDDLE PANEL (Live Activity Stream & Dossier)
        # -----------------------------------------------------
        mid_panel = ctk.CTkFrame(self, fg_color="transparent")
        mid_panel.grid(row=0, column=1, padx=8, pady=15, sticky="nsew")
        mid_panel.grid_rowconfigure(0, weight=1)
        mid_panel.grid_rowconfigure(1, weight=1)
        mid_panel.grid_columnconfigure(0, weight=1)

        # Feed Box
        feed_frame = ctk.CTkFrame(mid_panel, fg_color="#000000", corner_radius=0, border_width=1, border_color="#222222")
        feed_frame.grid(row=0, column=0, pady=(0, 10), sticky="nsew")

        ctk.CTkLabel(feed_frame, text="TELEMETRY STREAM", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), text_color="#ffffff").pack(anchor="w", padx=20, pady=(15, 8))

        self.feed_textbox = ctk.CTkTextbox(feed_frame, fg_color="#050505", text_color="#dddddd", font=ctk.CTkFont(family="Consolas", size=11), corner_radius=0, border_width=1, border_color="#1a1a1a")
        self.feed_textbox.pack(padx=15, pady=(0, 15), fill="both", expand=True)
        self.feed_textbox.configure(state="disabled")

        # Dossier Box
        dossier_frame = ctk.CTkFrame(mid_panel, fg_color="#000000", corner_radius=0, border_width=1, border_color="#222222")
        dossier_frame.grid(row=1, column=0, sticky="nsew")

        ctk.CTkLabel(dossier_frame, text="INCIDENT DOSSIER", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), text_color="#ffffff").pack(anchor="w", padx=20, pady=(15, 8))

        self.dossier_textbox = ctk.CTkTextbox(dossier_frame, fg_color="#050505", text_color="#10b981", font=ctk.CTkFont(family="Consolas", size=11), corner_radius=0, border_width=1, border_color="#1a1a1a")
        self.dossier_textbox.pack(padx=15, pady=(0, 15), fill="both", expand=True)
        self.dossier_textbox.configure(state="disabled")

        # -----------------------------------------------------
        # COLUMN 2: RIGHT PANEL (AI Neural Hub)
        # -----------------------------------------------------
        right_panel = ctk.CTkFrame(self, fg_color="#000000", corner_radius=0, border_width=1, border_color="#222222")
        right_panel.grid(row=0, column=2, padx=(8, 15), pady=15, sticky="nsew")
        right_panel.grid_rowconfigure(1, weight=1)
        right_panel.grid_columnconfigure(0, weight=1)

        # AI Header & Logo Box
        ai_header_frame = ctk.CTkFrame(right_panel, fg_color="#000000", corner_radius=0, border_width=1, border_color="#1a1a1a")
        ai_header_frame.pack(padx=18, pady=18, fill="x")

        ctk.CTkLabel(ai_header_frame, text="NEURAL ANALYST", font=ctk.CTkFont(family="Consolas", size=14, weight="bold"), text_color="#ffffff").pack(pady=(15, 5))
        
        logo_container = ctk.CTkFrame(ai_header_frame, fg_color="#000000", corner_radius=0)
        logo_container.pack(padx=15, pady=8, fill="x")
        
        self.ai_logo = WireframeDiamondCanvas(logo_container, size=120)
        self.ai_logo.pack(pady=10)
        
        ctk.CTkLabel(ai_header_frame, text="CORE: QWEN 27B", font=ctk.CTkFont(family="Consolas", size=10), text_color="#10b981").pack(pady=(0, 15))

        # AI Briefing Textbox Container
        ai_output_frame = ctk.CTkFrame(right_panel, fg_color="#000000", corner_radius=0, border_width=1, border_color="#1a1a1a")
        ai_output_frame.pack(padx=18, pady=(0, 18), fill="both", expand=True)

        ctk.CTkLabel(ai_output_frame, text="EXECUTIVE BRIEFING", font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), text_color="#ffffff").pack(anchor="w", padx=18, pady=(15, 8))

        self.ai_textbox = ctk.CTkTextbox(ai_output_frame, fg_color="#050505", text_color="#ffffff", font=ctk.CTkFont(family="Consolas", size=12), corner_radius=0, border_width=1, border_color="#1a1a1a")
        self.ai_textbox.pack(padx=15, pady=(0, 15), fill="both", expand=True)
        self.ai_textbox.configure(state="normal")
        self.ai_textbox.insert("end", "[SYS] Neural core online.\n[SYS] Standing by for telemetry data...\n")
        self.ai_textbox.configure(state="disabled")

        self._append_feed("[SYSTEM] Sentinel EDR initialized.\n")
        self._append_feed("[SYSTEM] Process hierarchy protected.\n")

    def _create_stat_badge(self, parent, label, init_val, color, col):
        card = ctk.CTkFrame(parent, fg_color="#000000", corner_radius=0, border_width=1, border_color="#1a1a1a")
        card.grid(row=0, column=col, padx=4, pady=4, sticky="nsew")
        val_lbl = ctk.CTkLabel(card, text=init_val, font=ctk.CTkFont(family="Consolas", size=22, weight="bold"), text_color=color)
        val_lbl.pack(pady=(10, 0))
        ctk.CTkLabel(card, text=label, font=ctk.CTkFont(family="Consolas", size=10), text_color="#777777").pack(pady=(0, 10))
        return val_lbl

    def _append_feed(self, text: str):
        self.feed_textbox.configure(state="normal")
        self.feed_textbox.insert("end", text)
        self.feed_textbox.see("end")
        self.feed_textbox.configure(state="disabled")

    def _render_dossier(self, event: dict):
        action = event.get("action_taken", "UNKNOWN")
        proc = event.get("process", {})
        threat_intel = event.get("threat_intelligence", {})
        anomalies = event.get("behavioral_anomalies", [])
        network = event.get("network", {})

        report = [
            "=====================================================",
            f" RECORD ID : {event.get('timestamp', 'N/A')}",
            "=====================================================",
            f" [STATUS]  : {action}",
            f" [TARGET]  : {proc.get('name', 'N/A')} (PID: {proc.get('pid', 'N/A')})",
            f" [HASH]    : {proc.get('sha256', 'N/A') or 'N/A'}",
            "-----------------------------------------------------",
            f" [INTEL]   : {threat_intel.get('verdict', 'N/A')} (Score: {threat_intel.get('score', 0)})",
            f" [ALERTS]  : {len(anomalies)} DETECTED"
        ]

        for i, a in enumerate(anomalies, 1):
            report.append(f"\n   > [{i}] RULE: {a.get('rule')} | MITRE: {a.get('mitre_id')}")
            report.append(f"     DATA: {a.get('description')}")

        remote_ips = network.get("remote_ips", [])
        if remote_ips:
            report.append(f"\n [NETWORK] : Active C2 blocked -> {', '.join(remote_ips)}")
        else:
            report.append("\n [NETWORK] : No external socket connected.")

        report.append("-----------------------------------------------------")
        if "KILLED" in action:
            report.append(" [LOG]     : Threat isolated and TERMINATED.")
        elif action == "RESUMED":
            report.append(" [LOG]     : Process VERIFIED BENIGN.")
        report.append("=====================================================")

        self.dossier_textbox.configure(state="normal")
        self.dossier_textbox.delete("1.0", "end")
        self.dossier_textbox.insert("end", "\n".join(report))
        self.dossier_textbox.configure(state="disabled")

    def _render_ai_briefing(self, ai_text: str):
        formatted_report = (
            "========================================\n"
            " NEURAL ANALYSIS LOG\n"
            "========================================\n\n"
            f"{ai_text}\n\n"
            "----------------------------------------\n"
            " [EOF]\n"
            "========================================"
        )
        self.ai_textbox.configure(state="normal")
        self.ai_textbox.delete("1.0", "end")
        self.ai_textbox.insert("end", formatted_report)
        self.ai_textbox.see("end")
        self.ai_textbox.configure(state="disabled")

    def _process_queue(self):
        try:
            while True:
                msg_type, payload = self.event_queue.get_nowait()
                now = datetime.now().strftime("%H:%M:%S")

                if msg_type == "INSPECTING":
                    pid, name = payload
                    self.agent_face.set_state("INSPECTING")
                    self.lbl_status.configure(text=f"STATUS: INSPECTING PID {pid}", text_color="#ffffff")
                    self._append_feed(f"[{now}] [SCAN] Anomaly in PID {pid} ({name}).\n")

                elif msg_type == "EVENT":
                    event = payload
                    self.last_event = event
                    action = event.get("action_taken", "UNKNOWN")
                    pid = event.get("process", {}).get("pid", "N/A")
                    name = event.get("process", {}).get("name", "N/A")

                    if "KILLED" in action:
                        self.agent_face.set_state("CONTAINING")
                        self.lbl_status.configure(text=f"STATUS: NEUTRALIZED PID {pid}", text_color="#ff0033")
                        curr = int(self.stat_threats.cget("text")) + 1
                        self.stat_threats.configure(text=str(curr))
                        self._append_feed(f"[{now}] [KILL] Terminated process: {name} (PID: {pid})\n")
                        self.after(3500, self._reset_patrol)

                    elif action == "RESUMED":
                        self.agent_face.set_state("SECURE")
                        self.lbl_status.configure(text=f"STATUS: VERIFIED PID {pid}", text_color="#10b981")
                        curr = int(self.stat_resumed.cget("text")) + 1
                        self.stat_resumed.configure(text=str(curr))
                        self._append_feed(f"[{now}] [SAFE] Process verified: {name} (PID: {pid})\n")
                        self.after(3000, self._reset_patrol)

                    self._render_dossier(event)

                elif msg_type == "AI_UPDATE":
                    ai_text = payload
                    self._render_ai_briefing(ai_text)

        except queue.Empty:
            pass

        self.after(150, self._process_queue)

    def _reset_patrol(self):
        self.agent_face.set_state("PATROLLING")
        self.lbl_status.configure(text="STATUS: PATROLLING", text_color="#10b981")

    # ---------------------------------------------------------
    # 4. BACKGROUND EDR THREAD WORKER & GROQ AI INTEGRATION
    # ---------------------------------------------------------
    def _start_edr_background_worker(self):
        def trigger_ai_triage(event_data, groq_key, preferred_model):
            if not groq_key or groq_key.startswith("YOUR_") or groq_key.startswith("PASTE_"):
                self.event_queue.put(("AI_UPDATE", "[!] AI Analyst disabled: Missing API key."))
                return

            try:
                proc = event_data.get("process", {})
                intel = event_data.get("threat_intelligence", {})
                anomalies = event_data.get("behavioral_anomalies", [])
                action = event_data.get("action_taken", "UNKNOWN")

                prompt = (
                    f"You are an elite Senior SOC Cyber Threat Analyst reviewing an endpoint incident caught by Sentinel EDR.\n"
                    f"Process Name: {proc.get('name')} (PID: {proc.get('pid')})\n"
                    f"SHA-256 Hash: {proc.get('sha256')}\n"
                    f"VirusTotal Verdict: {intel.get('verdict')} (Score: {intel.get('score')})\n"
                    f"Behavioral Detections: {anomalies}\n"
                    f"Containment Action: {action}\n\n"
                    f"Provide a crisp, hard-hitting executive technical briefing explaining the adversarial technique "
                    f"attempted, its risk level, and confirmation of containment efficacy. Use a highly professional, structured tone."
                )

                headers = {
                    "Authorization": f"Bearer {groq_key.strip()}",
                    "Content-Type": "application/json"
                }

                candidate_models = [
                    preferred_model,
                    "qwen/qwen3.8-27b",
                    "openai/gpt-oss-20b",
                    "openai/gpt-oss-120b"
                ]

                last_error = ""
                for model_candidate in candidate_models:
                    if not model_candidate:
                        continue
                    payload = {
                        "model": model_candidate,
                        "messages": [
                            {"role": "system", "content": "You are a professional SOC incident responder formatting concise reports."},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.2,
                        "max_tokens": 600
                    }

                    res = requests.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers=headers,
                        json=payload,
                        timeout=10
                    )

                    if res.status_code == 200:
                        data = res.json()
                        ai_text = data["choices"][0]["message"]["content"].strip()
                        self.event_queue.put(("AI_UPDATE", ai_text))
                        return
                    else:
                        last_error = f"HTTP {res.status_code}: {res.text}"
                        continue

                self.event_queue.put(("AI_UPDATE", f"[!] Groq API Error: {last_error}"))

            except Exception as e:
                self.event_queue.put(("AI_UPDATE", f"[!] AI Analyst Query Error: {e}"))

        def edr_loop():
            config_file = Path("config/settings.json")
            if not config_file.exists():
                return

            with open(config_file, "r", encoding="utf-8") as f:
                settings = json.load(f)

            scan_interval = settings["general"]["scan_interval_seconds"]
            whitelist = settings["system_whitelist"]

            rule_engine = BehavioralRuleEngine(system_whitelist=whitelist)
            containment_engine = ContainmentEngine(log_path=settings["general"]["log_file"])

            vt_config = settings["threat_intel"]
            vt_client = VirusTotalClient(
                api_key=vt_config["virustotal_api_key"],
                endpoint_url=vt_config["vt_url"],
                threshold=vt_config["malicious_threshold"],
                cache_ttl=vt_config["cache_ttl_hours"]
            )

            ai_cfg = settings.get("ai_analyst", {})
            groq_key = ai_cfg.get("groq_api_key", "")
            groq_model = ai_cfg.get("model", "qwen/qwen3.8-27b")

            excluded_pids = {os.getpid()}
            try:
                for ancestor in psutil.Process(os.getpid()).parents():
                    excluded_pids.add(ancestor.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            handled_pids = set()

            while self.is_running:
                active_pids = set(psutil.pids())
                handled_pids.intersection_update(active_pids)

                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        if proc.pid in excluded_pids or proc.pid in handled_pids:
                            continue

                        anomalies = rule_engine.evaluate_process(proc)

                        if anomalies:
                            handled_pids.add(proc.pid)
                            self.event_queue.put(("INSPECTING", (proc.pid, proc.name())))

                            exe_path = proc.exe() if proc.exe() else ""
                            file_hash = ""
                            if exe_path and Path(exe_path).is_file():
                                try:
                                    hasher = hashlib.sha256()
                                    with open(exe_path, "rb") as bf:
                                        while chunk := bf.read(8192):
                                            hasher.update(chunk)
                                    file_hash = hasher.hexdigest()
                                except (PermissionError, OSError):
                                    file_hash = ""

                            active_ips = []
                            try:
                                for conn in proc.net_connections(kind="inet"):
                                    if conn.raddr and conn.raddr.ip and not conn.raddr.ip.startswith("127."):
                                        active_ips.append(conn.raddr.ip)
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass

                            intel_result = vt_client.query_hash(file_hash)

                            action_result = containment_engine.handle_incident(
                                proc, anomalies, intel_result, file_hash, active_ips
                            )

                            self.event_queue.put(("EVENT", action_result))

                            ai_thread = threading.Thread(
                                target=trigger_ai_triage,
                                args=(action_result, groq_key, groq_model),
                                daemon=True
                            )
                            ai_thread.start()

                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

                time.sleep(scan_interval)

        thread = threading.Thread(target=edr_loop, daemon=True)
        thread.start()


if __name__ == "__main__":
    app = UnifiedSentinelApp()
    app.mainloop()