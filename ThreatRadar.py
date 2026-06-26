import customtkinter as ctk
import requests
import re
import time
import base64
import os
import json

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

CONFIG_FILE = "config.json"

def load_api_key():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f).get("api_key", "")
    return ""

def save_api_key(key):
    with open(CONFIG_FILE, "w") as f:
        json.dump({"api_key": key}, f)


class APIKeySetup(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("THREAT RADAR // SETUP")
        self.geometry("500x300")
        self.configure(fg_color="#08080A")
        self.resizable(False, False)
        self.grab_set()

        ctk.CTkLabel(self, text="⚡ THREAT RADAR //",
                     font=("Consolas", 22, "bold"), text_color="#00FF66").pack(pady=(30, 5))

        ctk.CTkLabel(self, text="Enter your VirusTotal API Key to get started:",
                     font=("Consolas", 12), text_color="#8F94A0").pack(pady=(10, 5))

        self.key_entry = ctk.CTkEntry(self, width=380, height=40,
                                      fg_color="#0B0C0E", border_color="#22252E",
                                      font=("Consolas", 12), text_color="#E2E4E9",
                                      placeholder_text="Paste your API key here...")
        self.key_entry.pack(pady=10, padx=40)

        ctk.CTkLabel(self, text="Get your free key at: virustotal.com → Profile → API Key",
                     font=("Consolas", 10), text_color="#626773").pack(pady=(0, 15))

        ctk.CTkButton(self, text="SAVE & LAUNCH",
                      command=self.save_and_close,
                      font=("Consolas", 13, "bold"),
                      fg_color="#00FF66", text_color="#08080A",
                      hover_color="#00CC52", height=40, width=200).pack()

    def save_and_close(self):
        key = self.key_entry.get().strip()
        if key:
            save_api_key(key)
            self.destroy()


class CyberThreatAnalyzer(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("THREAT RADAR // LIVE API INTELLIGENCE SYSTEM")
        self.geometry("900x700")
        self.configure(fg_color="#08080A")

        self.HIDDEN_API_KEY = load_api_key()

        self.THRESHOLDS = {
            "CRITICAL": 75,
            "HIGH":     50,
            "MEDIUM":   25,
            "LOW":      10,
        }

        # إذا ما في مفتاح محفوظ، افتح شاشة الإعداد
        if not self.HIDDEN_API_KEY:
            self.after(100, self.show_setup)

        self._build_ui()

    def show_setup(self):
        setup = APIKeySetup(self)
        self.wait_window(setup)
        self.HIDDEN_API_KEY = load_api_key()

    def _build_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(pady=20, fill="x", padx=40)

        ctk.CTkLabel(header, text="⚡ THREAT RADAR //",
                     font=("Consolas", 28, "bold"), text_color="#00FF66").pack(side="left")

        # زر إعادة ضبط المفتاح
        ctk.CTkButton(header, text="⚙ API KEY", command=self.show_setup,
                      font=("Consolas", 11), fg_color="#1A1C23",
                      text_color="#8F94A0", hover_color="#22252E",
                      height=30, width=90, corner_radius=4).pack(side="right", pady=5, padx=(5,0))

        ctk.CTkLabel(header, text=" API MODE: LIVE DATABASE ",
                     font=("Consolas", 12, "bold"), text_color="#08080A",
                     fg_color="#00FF66", corner_radius=4).pack(side="right", pady=5)

        input_frame = ctk.CTkFrame(self, fg_color="#101114", border_width=1,
                                   border_color="#1A1C23", corner_radius=12)
        input_frame.pack(pady=10, fill="x", padx=40)

        ctk.CTkLabel(input_frame, text="[+] ENTER TARGET URL FOR LIVE SECURITY AUDIT:",
                     font=("Consolas", 13), text_color="#8F94A0").pack(anchor="w", padx=20, pady=(15, 5))

        self.input_box = ctk.CTkTextbox(input_frame, width=730, height=100,
                                        fg_color="#0B0C0E", border_width=1,
                                        border_color="#22252E", corner_radius=8,
                                        font=("Consolas", 13), text_color="#E2E4E9")
        self.input_box.pack(pady=(0, 20), padx=20)

        ctk.CTkButton(self, text="EXECUTE REAL-TIME SCAN", command=self.execute_scan,
                      font=("Consolas", 15, "bold"), fg_color="#00FF66",
                      text_color="#08080A", hover_color="#00CC52",
                      corner_radius=6, height=45, width=250).pack(pady=10)

        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=40, pady=10)

        self.severity_panel = ctk.CTkFrame(container, width=200, fg_color="#101114",
                                           border_width=1, border_color="#1A1C23", corner_radius=12)
        self.severity_panel.pack(side="left", fill="both", expand=False)
        self.severity_panel.pack_propagate(False)

        ctk.CTkLabel(self.severity_panel, text="VERDICT RISK",
                     font=("Consolas", 12, "bold"), text_color="#8F94A0").pack(pady=(15, 2), padx=25)

        self.sev_status = ctk.CTkLabel(self.severity_panel, text="IDLE",
                                       font=("Consolas", 22, "bold"), text_color="#8F94A0")
        self.sev_status.pack(pady=(10, 2), padx=25)

        ctk.CTkLabel(self.severity_panel, text="THREAT SCORE",
                     font=("Consolas", 10), text_color="#626773").pack(pady=(15, 2))

        self.score_label = ctk.CTkLabel(self.severity_panel, text="--",
                                        font=("Consolas", 32, "bold"), text_color="#8F94A0")
        self.score_label.pack()

        ctk.CTkLabel(self.severity_panel, text="/ 100",
                     font=("Consolas", 11), text_color="#626773").pack(pady=(0, 10))

        self.score_bar = ctk.CTkProgressBar(self.severity_panel, width=150, height=12,
                                            progress_color="#00FF66", fg_color="#1A1C23")
        self.score_bar.pack(pady=(0, 20), padx=20)
        self.score_bar.set(0)

        ctk.CTkLabel(self.severity_panel, text="── LEVELS ──",
                     font=("Consolas", 9), text_color="#3A3D47").pack(pady=(5, 5))

        levels = [
            ("■ 0–9    SECURE",   "#00FF66"),
            ("■ 10–24  LOW",      "#66CCFF"),
            ("■ 25–49  MEDIUM",   "#FFCC00"),
            ("■ 50–74  HIGH",     "#FF8800"),
            ("■ 75–100 CRITICAL", "#FF3333"),
        ]
        for txt, col in levels:
            ctk.CTkLabel(self.severity_panel, text=txt,
                         font=("Consolas", 9), text_color=col).pack(anchor="w", padx=18, pady=1)

        report_panel = ctk.CTkFrame(container, fg_color="#101114", border_width=1,
                                    border_color="#1A1C23", corner_radius=12)
        report_panel.pack(side="right", fill="both", expand=True, padx=(15, 0))

        ctk.CTkLabel(report_panel, text="VIRUSTOTAL ANALYSIS REPORT //",
                     font=("Consolas", 12, "bold"), text_color="#8F94A0").pack(anchor="w", padx=20, pady=15)

        self.result_output = ctk.CTkTextbox(report_panel, fg_color="transparent",
                                            border_width=0, font=("Consolas", 12),
                                            text_color="#626773", activate_scrollbars=True)
        self.result_output.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self.result_output.insert("1.0", "Awaiting target URL input...")

    def calculate_threat_score(self, stats, total_engines):
        if not stats or total_engines == 0:
            return 0
        malicious  = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        mal_ratio  = malicious  / total_engines
        sus_ratio  = suspicious / total_engines
        raw_score  = (mal_ratio * 80) + (sus_ratio * 30)
        if malicious >= 3:
            raw_score += 15
        elif malicious >= 1:
            raw_score += 5
        return min(100, int(raw_score))

    def get_verdict_from_score(self, score):
        if score >= self.THRESHOLDS["CRITICAL"]:
            return "CRITICAL", "#FF3333"
        elif score >= self.THRESHOLDS["HIGH"]:
            return "HIGH RISK", "#FF8800"
        elif score >= self.THRESHOLDS["MEDIUM"]:
            return "MEDIUM", "#FFCC00"
        elif score >= self.THRESHOLDS["LOW"]:
            return "LOW RISK", "#66CCFF"
        else:
            return "SECURE", "#00FF66"

    def extract_urls(self, text):
        return re.findall(r'(https?://\S+)', text)

    def scan_url_via_vt(self, url):
        url_id  = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"accept": "application/json", "x-apikey": self.HIDDEN_API_KEY}

        try:
            response = requests.get(api_url, headers=headers)
            if response.status_code == 200:
                data_attr = response.json()['data']['attributes']
                return data_attr.get('last_analysis_stats', {}), data_attr.get('last_analysis_results', {})

            elif response.status_code == 404:
                post_headers = {**headers, "content-type": "application/x-www-form-urlencoded"}
                post_resp    = requests.post("https://www.virustotal.com/api/v3/urls",
                                             data={"url": url}, headers=post_headers)
                if post_resp.status_code == 200:
                    analysis_id = post_resp.json()['data']['id']
                    attr = {}
                    for _ in range(5):
                        time.sleep(3)
                        res = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                                           headers=headers)
                        if res.status_code == 200:
                            attr = res.json()['data']['attributes']
                            if attr['status'] == "completed":
                                return attr.get('stats', {}), attr.get('results', {})
                            if attr.get('stats', {}).get('malicious', 0) > 0:
                                return attr.get('stats', {}), attr.get('results', {})
                    return attr.get('stats', {}), attr.get('results', {})
            return None, None
        except Exception:
            return "error", None

    def execute_scan(self):
        user_input = self.input_box.get("1.0", "end-1c").strip()
        self.result_output.delete("1.0", "end")

        if not user_input:
            self.sev_status.configure(text="ERROR", text_color="#FF3333")
            self.result_output.insert("1.0", "[-] Action required: Input URL cannot be empty.")
            return

        self.sev_status.configure(text="QUERYING", text_color="#FFCC00")
        self.score_label.configure(text="...", text_color="#FFCC00")
        self.score_bar.set(0)
        self.result_output.insert("1.0", "[*] Contacting global anti-malware databases...\n    Please wait...")
        self.update()

        urls = self.extract_urls(user_input)
        if not urls:
            self.sev_status.configure(text="NO URL", text_color="#FFCC00")
            self.result_output.delete("1.0", "end")
            self.result_output.insert("1.0", "[-] Error: Enter a valid URL containing http:// or https://")
            return

        target_url     = urls[0]
        stats, results = self.scan_url_via_vt(target_url)
        self.result_output.delete("1.0", "end")

        if stats == "error":
            self.sev_status.configure(text="FAIL", text_color="#FF3333")
            self.result_output.insert("1.0", "[-] Connection Error: Invalid API key or network timeout.")
            return

        if not stats:
            self.sev_status.configure(text="UNKNOWN", text_color="#8F94A0")
            self.result_output.insert("1.0", "[-] No threat data found for this URL.")
            return

        malicious  = stats.get('malicious',  0)
        suspicious = stats.get('suspicious', 0)
        harmless   = stats.get('harmless',   0)
        undetected = stats.get('undetected', 0)
        total      = malicious + suspicious + harmless + undetected

        score          = self.calculate_threat_score(stats, total if total > 0 else 1)
        verdict, color = self.get_verdict_from_score(score)

        self.sev_status.configure(text=verdict, text_color=color)
        self.score_label.configure(text=str(score), text_color=color)
        self.score_bar.configure(progress_color=color)
        self.score_bar.set(score / 100)

        report  = f"[+] Target Audited : {target_url}\n"
        report += f"{'='*55}\n"
        report += f"[📊] THREAT SCORE  : {score}/100  →  {verdict}\n"
        report += f"{'='*55}\n"
        report += f"[📡] DETECTION STATS ({total} engines):\n"
        report += f"    ⚠  Malicious  : {malicious}\n"
        report += f"    ❓  Suspicious : {suspicious}\n"
        report += f"    ✅  Clean      : {harmless + undetected}\n"
        report += f"{'='*55}\n\n"

        if score >= self.THRESHOLDS["CRITICAL"]:
            report += "[🚨] VERDICT: CRITICAL THREAT DETECTED!\n\n"
        elif score >= self.THRESHOLDS["HIGH"]:
            report += "[🔴] VERDICT: HIGH RISK — Exercise extreme caution.\n\n"
        elif score >= self.THRESHOLDS["MEDIUM"]:
            report += "[🟡] VERDICT: MEDIUM RISK — Suspicious activity detected.\n\n"
        elif score >= self.THRESHOLDS["LOW"]:
            report += "[🔵] VERDICT: LOW RISK — Minor signals, likely safe.\n\n"
        else:
            report += "[✅] VERDICT: CLEAN & SECURE\n"
            report += "    No active malicious records found.\n\n"

        if malicious > 0 and results:
            report += "[🛡️] ENGINES THAT FLAGGED THIS TARGET:\n"
            count = 1
            for engine_name, engine_data in results.items():
                if engine_data.get('category') == 'malicious':
                    report += f"  {count}. [{engine_name.upper()}] → {engine_data.get('result')}\n"
                    count += 1
            report += "\n"

        if suspicious > 0 and results:
            report += "[⚠️] ENGINES THAT FLAGGED AS SUSPICIOUS:\n"
            count = 1
            for engine_name, engine_data in results.items():
                if engine_data.get('category') == 'suspicious':
                    report += f"  {count}. [{engine_name.upper()}] → {engine_data.get('result')}\n"
                    count += 1

        self.result_output.insert("1.0", report)


if __name__ == "__main__":
    app = CyberThreatAnalyzer()
    app.mainloop()
