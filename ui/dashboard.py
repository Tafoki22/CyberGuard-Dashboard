# ui/dashboard.py
import customtkinter as ctk
import threading
import os
import time
import random
from datetime import datetime, timedelta
from tkinter import messagebox

# Graphing Library
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Modules
from modules.scanner import run_network_scan 
from modules.email_check import check_email_for_breaches, get_breach_history
from modules.dns_scanner import check_domain_security
from modules.web_scanner import scan_website
from modules.auto_engine import AutomatedEngine
from modules.enterprise import authenticate_organization, get_enterprise_dashboard_data
from modules.auth import login_user, create_user_final, check_email_availability, validate_password_strength, validate_email_format
from modules.otp_service import generate_otp, send_otp_email
from modules.analytics import get_activity_data_last_7_days, get_security_posture_score
from tools.pidgin import get_general_greeting
from tools.reporting import generate_compliance_report, clear_all_data 

class CyberGuardDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CyberGuard Dashboard - S-VCG Edition")
        self.geometry("1200x850")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        self.auto_engine = AutomatedEngine()
        self.current_user_email = None
        self.running = True 
        
        # Temp Storage for Registration
        self.reg_temp_data = {}
        self.reg_otp_code = None
        self.reset_otp = None
        self.reset_email = None
        
        # Initialize UI Variables (Prevents AttributeErrors)
        self.report_status = None
        self.scan_results_textbox = None
        self.metric_labels = {}
        
        # --- FRAMES ---
        self.login_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.register_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.forgot_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.app_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        
        self.build_login_screen()
        self.build_register_screen()
        self.build_forgot_password_screen()
        self.build_main_app()

        # Start Animation Thread (System Health)
        threading.Thread(target=self.animate_system_health, daemon=True).start()

        self.show_login()

    # --- NAVIGATION ---
    def show_login(self): self.hide_all(); self.login_frame.grid(row=0, column=0, sticky="nsew")
    def show_register(self): self.hide_all(); self.register_frame.grid(row=0, column=0, sticky="nsew")
    def show_forgot(self): self.hide_all(); self.forgot_frame.grid(row=0, column=0, sticky="nsew")
    def show_app(self): self.hide_all(); self.app_frame.grid(row=0, column=0, sticky="nsew"); self.refresh_dashboard_data()
    def hide_all(self): 
        for f in [self.login_frame, self.register_frame, self.forgot_frame, self.app_frame]: f.grid_forget()

    # ==========================================
    # 🔐 AUTHENTICATION SCREENS
    # ==========================================
    def build_login_screen(self):
        box = ctk.CTkFrame(self.login_frame, width=400, height=550)
        box.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(box, text="CyberGuard Login", font=("Roboto", 24, "bold")).pack(pady=(40, 10))
        self.entry_login_email = ctk.CTkEntry(box, placeholder_text="Business Email", width=300); self.entry_login_email.pack(pady=10)
        self.entry_login_pass = ctk.CTkEntry(box, placeholder_text="Password", show="*", width=300); self.entry_login_pass.pack(pady=10)
        ctk.CTkButton(box, text="Login", command=self.perform_login, width=300).pack(pady=20)
        link_frame = ctk.CTkFrame(box, fg_color="transparent"); link_frame.pack(pady=5)
        ctk.CTkButton(link_frame, text="Forgot Password?", fg_color="transparent", text_color="cyan", width=120, command=self.show_forgot).pack(side="left")
        ctk.CTkButton(link_frame, text="Create Account", fg_color="transparent", text_color="cyan", width=120, command=self.show_register).pack(side="right")
        self.lbl_login_msg = ctk.CTkLabel(box, text="", text_color="red"); self.lbl_login_msg.pack(pady=5)
        ctk.CTkSwitch(box, text="Dark Mode", command=self.toggle_theme, onvalue="on", offvalue="off").pack(pady=20)

    def build_register_screen(self):
        box = ctk.CTkFrame(self.register_frame, width=400, height=600)
        box.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(box, text="Create Account", font=("Roboto", 24, "bold")).pack(pady=(30, 20))
        
        # Step 1 View
        self.reg_step1 = ctk.CTkFrame(box, fg_color="transparent"); self.reg_step1.pack(fill="both", expand=True)
        self.entry_reg_email = ctk.CTkEntry(self.reg_step1, placeholder_text="Business Email", width=300); self.entry_reg_email.pack(pady=10)
        self.entry_reg_org = ctk.CTkEntry(self.reg_step1, placeholder_text="Organization Name", width=300); self.entry_reg_org.pack(pady=10)
        self.entry_reg_pass = ctk.CTkEntry(self.reg_step1, placeholder_text="Strong Password", show="*", width=300); self.entry_reg_pass.pack(pady=10)
        ctk.CTkButton(self.reg_step1, text="Verify Email (Send OTP)", command=self.perform_reg_step1, width=300).pack(pady=20)
        
        # Step 2 View (Hidden initially)
        self.reg_step2 = ctk.CTkFrame(box, fg_color="transparent") 
        ctk.CTkLabel(self.reg_step2, text="Enter Verification Code", font=("Arial", 14)).pack(pady=10)
        self.entry_reg_otp = ctk.CTkEntry(self.reg_step2, placeholder_text="6-Digit OTP", width=300); self.entry_reg_otp.pack(pady=10)
        ctk.CTkButton(self.reg_step2, text="Verify & Create Account", command=self.perform_reg_step2, width=300).pack(pady=20)
        ctk.CTkButton(self.reg_step2, text="Back", fg_color="transparent", command=self.reset_reg_view).pack()

        self.lbl_reg_msg = ctk.CTkLabel(box, text="", text_color="red"); self.lbl_reg_msg.pack(pady=5)
        self.btn_reg_back = ctk.CTkButton(box, text="Back to Login", fg_color="transparent", border_width=1, command=self.show_login); self.btn_reg_back.pack(pady=10)

    def build_forgot_password_screen(self):
        self.forgot_box = ctk.CTkFrame(self.forgot_frame, width=400, height=500)
        self.forgot_box.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(self.forgot_box, text="Reset Password", font=("Roboto", 24, "bold")).pack(pady=(30, 10))
        self.step1_frame = ctk.CTkFrame(self.forgot_box, fg_color="transparent"); self.step1_frame.pack(fill="both", expand=True, padx=20)
        self.entry_reset_email = ctk.CTkEntry(self.step1_frame, placeholder_text="Registered Email", width=300); self.entry_reset_email.pack(pady=20)
        ctk.CTkButton(self.step1_frame, text="Send OTP", command=self.send_reset_otp).pack(pady=10)
        self.step2_frame = ctk.CTkFrame(self.forgot_box, fg_color="transparent")
        self.entry_otp = ctk.CTkEntry(self.step2_frame, placeholder_text="Enter OTP", width=300); self.entry_otp.pack(pady=10)
        self.entry_new_pass = ctk.CTkEntry(self.step2_frame, placeholder_text="New Password", show="*", width=300); self.entry_new_pass.pack(pady=10)
        ctk.CTkButton(self.step2_frame, text="Verify & Update", command=self.verify_and_update_password).pack(pady=20)
        self.lbl_forgot_msg = ctk.CTkLabel(self.forgot_box, text="", text_color="red"); self.lbl_forgot_msg.pack(pady=10)
        ctk.CTkButton(self.forgot_box, text="Back", fg_color="transparent", command=self.show_login).pack(pady=10)

    # --- AUTH LOGIC ---
    def perform_login(self):
        if login_user(self.entry_login_email.get(), self.entry_login_pass.get())[0]: self.show_app(); self.log_system_event("User Logged In")
        else: self.lbl_login_msg.configure(text="Invalid Credentials")

    def reset_reg_view(self):
        self.reg_step2.pack_forget(); self.reg_step1.pack(fill="both", expand=True); self.btn_reg_back.pack(pady=10); self.lbl_reg_msg.configure(text="")

    def perform_reg_step1(self):
        email = self.entry_reg_email.get().strip()
        pwd = self.entry_reg_pass.get().strip()
        org = self.entry_reg_org.get().strip()
        if not validate_email_format(email): self.lbl_reg_msg.configure(text="Invalid Email Format", text_color="red"); return
        if not validate_password_strength(pwd)[0]: self.lbl_reg_msg.configure(text="Weak Password", text_color="red"); return
        if not check_email_availability(email)[0]: self.lbl_reg_msg.configure(text="Email Taken", text_color="red"); return

        otp = generate_otp()
        if send_otp_email(email, otp)[0]:
            self.reg_temp_data = {"email": email, "pass": pwd, "org": org}; self.reg_otp_code = otp
            self.lbl_reg_msg.configure(text="OTP Sent!", text_color="green")
            self.reg_step1.pack_forget(); self.btn_reg_back.pack_forget(); self.reg_step2.pack(fill="both", expand=True)
        else: self.lbl_reg_msg.configure(text="Error Sending Email", text_color="red")

    def perform_reg_step2(self):
        if self.entry_reg_otp.get().strip() == self.reg_otp_code:
            d = self.reg_temp_data
            if create_user_final(d['email'], d['pass'], d['org'])[0]:
                self.lbl_reg_msg.configure(text="Success! Login now.", text_color="green")
                self.after(1500, self.show_login); self.reset_reg_view()
            else: self.lbl_reg_msg.configure(text="DB Error", text_color="red")
        else: self.lbl_reg_msg.configure(text="Invalid OTP", text_color="red")

    def send_reset_otp(self):
        email = self.entry_reset_email.get().strip()
        if not check_email_availability(email)[0]: # False means email taken
            otp = generate_otp()
            if send_otp_email(email, otp)[0]:
                self.reset_otp = otp; self.reset_email = email
                self.lbl_forgot_msg.configure(text="OTP Sent!", text_color="green")
                self.step1_frame.pack_forget(); self.step2_frame.pack(fill="both", expand=True, padx=20)
            else: self.lbl_forgot_msg.configure(text="Error Sending OTP", text_color="red")
        else: self.lbl_forgot_msg.configure(text="Email not found.", text_color="red")

    def verify_and_update_password(self):
        if self.entry_otp.get().strip() == self.reset_otp:
            from database.models import User
            from database.db_session import create_session
            from modules.auth import hash_password
            session = create_session()
            user = session.query(User).filter(User.email == self.reset_email).first()
            if user:
                user.password_hash = hash_password(self.entry_new_pass.get().strip())
                session.commit()
                self.lbl_forgot_msg.configure(text="Password Updated!", text_color="green"); self.after(2000, self.show_login)
            else: self.lbl_forgot_msg.configure(text="User Error", text_color="red")
            session.close()
        else: self.lbl_forgot_msg.configure(text="Invalid OTP", text_color="red")

    # ==========================================
    # 🖥️ MAIN APP
    # ==========================================
    def build_main_app(self):
        self.tab_view = ctk.CTkTabview(self.app_frame, width=1150, height=750)
        self.tab_view.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        for t in ["Dashboard", "Network Scanner", "Web Security", "Breach Monitor", "DNS Security", "Enterprise", "Settings"]: self.tab_view.add(t)
        
        # --- DASHBOARD ---
        dash = self.tab_view.tab("Dashboard")
        head = ctk.CTkFrame(dash, fg_color="transparent"); head.pack(pady=10, fill="x", padx=20)
        ctk.CTkLabel(head, text="🇳🇬 National Threat Analytics", font=("Roboto", 20, "bold")).pack(side="left")
        ctk.CTkButton(head, text="🔄 Refresh Data", width=100, command=self.refresh_dashboard_data).pack(side="right")
        self.metrics_frame = ctk.CTkFrame(dash); self.metrics_frame.pack(pady=10, padx=20, fill="x")
        self.metric_labels = {}
        self.create_metric_card(self.metrics_frame, "Security Score", "...", "gray", 0)
        self.create_metric_card(self.metrics_frame, "System Status", "...", "gray", 1)
        self.create_metric_card(self.metrics_frame, "Threats Blocked", "...", "gray", 2)
        self.graph_frame = ctk.CTkFrame(dash); self.graph_frame.pack(pady=20, padx=20, fill="both", expand=True)

        # --- NETWORK SCANNER ---
        scan = self.tab_view.tab("Network Scanner")
        ctk.CTkLabel(scan, text=get_general_greeting(), text_color="#00FF00", font=("Consolas", 14)).pack(pady=5)
        self.consent_var = ctk.BooleanVar()
        ctk.CTkCheckBox(scan, text="I authorize this scan (Cybercrimes Act 2015).", variable=self.consent_var).pack(pady=5)
        self.progress_bar = ctk.CTkProgressBar(scan, width=400, mode="indeterminate"); self.progress_bar.pack(pady=5); self.progress_bar.pack_forget()
        ctk.CTkButton(scan, text="🚀 Start Deep Scan", command=self.start_scan_thread).pack(pady=10)
        self.scan_status = ctk.StringVar(value="Ready."); ctk.CTkLabel(scan, textvariable=self.scan_status).pack(pady=5)
        self.scan_results_textbox = ctk.CTkTextbox(scan, width=800, height=350, text_color="#E0E0E0", fg_color="#0D0D0D", font=("Consolas", 12))
        self.scan_results_textbox.pack(padx=10, pady=10, fill="both", expand=True)
        for tag, col in [("header","#3B8ED0"),("high_risk","#FF5555"),("medium_risk","#FFAA00"),("low_risk","#00FF00"),("remediation","#00FFFF")]:
            self.scan_results_textbox.tag_config(tag, foreground=col)
        self.scan_results_textbox.insert("end", "> SYSTEM INITIALIZED.\n> READY TO SCAN LOCAL HOSTS...\n\n", "low_risk")

        # --- WEB SECURITY ---
        web = self.tab_view.tab("Web Security")
        ctk.CTkLabel(web, text="Web Vulnerability Scanner (VulnaScan Core)", font=("Roboto", 18, "bold")).pack(pady=10)
        web_in = ctk.CTkFrame(web); web_in.pack(pady=10, padx=20, fill="x")
        self.web_url = ctk.CTkEntry(web_in, placeholder_text="e.g. http://testphp.vulnweb.com", width=400); self.web_url.pack(side="left", padx=10)
        ctk.CTkButton(web_in, text="🔍 Scan Website", command=self.start_web_scan).pack(side="left")
        self.web_status = ctk.StringVar(value="Ready to scan."); ctk.CTkLabel(web, textvariable=self.web_status).pack(pady=5)
        self.web_results = ctk.CTkTextbox(web, width=800, height=350, font=("Consolas", 12), fg_color="#0D0D0D", text_color="#E0E0E0")
        self.web_results.pack(fill="both", expand=True, padx=10, pady=(0,10))
        for tag, col in [("safe","#00FF00"),("warn","#FFAA00"),("crit","#FF5555"),("info","#3B8ED0")]: self.web_results.tag_config(tag, foreground=col)

        # --- BREACH MONITOR ---
        breach = self.tab_view.tab("Breach Monitor")
        b_head = ctk.CTkFrame(breach, fg_color="transparent"); b_head.pack(pady=10, fill="x", padx=20)
        self.email_entry = ctk.CTkEntry(b_head, placeholder_text="Enter Email", width=300, font=("Arial", 14)); self.email_entry.pack(side="left", padx=(0,10))
        ctk.CTkButton(b_head, text="🔍 Deep Scan", width=120, command=self.check_breach_thread).pack(side="left")
        self.monitor_var = ctk.StringVar(value="off")
        self.monitor_switch = ctk.CTkSwitch(b_head, text="24/7 Active Monitoring", command=self.toggle_email_monitoring, variable=self.monitor_var, onvalue="on", offvalue="off", progress_color="#00FF00")
        self.monitor_switch.pack(side="right")
        self.status_card = ctk.CTkFrame(breach, height=100, fg_color="#1A1A1A"); self.status_card.pack(fill="x", padx=20, pady=10)
        self.lbl_status_icon = ctk.CTkLabel(self.status_card, text="🛡️", font=("Arial", 40)); self.lbl_status_icon.pack(side="left", padx=20, pady=10)
        self.lbl_status_title = ctk.CTkLabel(self.status_card, text="SYSTEM READY", font=("Roboto", 20, "bold"), text_color="gray"); self.lbl_status_title.pack(side="left", anchor="w", pady=(10,0))
        self.lbl_status_desc = ctk.CTkLabel(self.status_card, text="Awaiting Input...", font=("Arial", 12)); self.lbl_status_desc.place(x=90, y=45)
        self.breach_history_textbox = ctk.CTkTextbox(breach, width=800, height=350, font=("Consolas", 13), fg_color="#0D0D0D", text_color="#E0E0E0")
        self.breach_history_textbox.pack(fill="both", expand=True, padx=20, pady=(0,20))
        for tag, col in [("safe","#00FF00"),("crit","#FF5555"),("step","#00FFFF")]: self.breach_history_textbox.tag_config(tag, foreground=col)
        self.update_breach_history_ui()

        # --- DNS SECURITY ---
        dns = self.tab_view.tab("DNS Security")
        d_head = ctk.CTkFrame(dns, fg_color="transparent"); d_head.pack(pady=10, fill="x", padx=20)
        ctk.CTkLabel(d_head, text="Domain Threat Matrix", font=("Roboto", 20, "bold")).pack(side="left")
        d_in = ctk.CTkFrame(dns); d_in.pack(pady=10, padx=20, fill="x")
        self.dns_entry = ctk.CTkEntry(d_in, placeholder_text="e.g. nitda.gov.ng", width=300); self.dns_entry.pack(side="left", padx=10, pady=10)
        self.dns_consent_var = ctk.BooleanVar(); ctk.CTkCheckBox(d_in, text="Authorized Audit", variable=self.dns_consent_var).pack(side="left", padx=10)
        ctk.CTkButton(d_in, text="🛡️ Run Matrix Audit", command=self.run_dns_audit).pack(side="right", padx=10)
        self.matrix_frame = ctk.CTkFrame(dns, fg_color="transparent"); self.matrix_frame.pack(pady=10, padx=10, fill="x")
        self.card_spf = self.create_threat_card(self.matrix_frame, "SPF Record", "Unknown", "gray", 0)
        self.card_dmarc = self.create_threat_card(self.matrix_frame, "DMARC Policy", "Unknown", "gray", 1)
        self.card_dnssec = self.create_threat_card(self.matrix_frame, "DNSSEC Integrity", "Unknown", "gray", 2)
        self.card_latency = self.create_threat_card(self.matrix_frame, "Res. Latency", "0ms", "gray", 3)
        self.dns_mitigation_box = ctk.CTkTextbox(dns, width=800, height=250, font=("Consolas", 12), fg_color="#0D0D0D", text_color="#E0E0E0")
        self.dns_mitigation_box.pack(fill="both", expand=True, padx=20, pady=(0,20))
        for tag, col in [("fix","#00FFFF"),("warn","#FF5555"),("safe","#00FF00")]: self.dns_mitigation_box.tag_config(tag, foreground=col)

        # --- ENTERPRISE (SOC) ---
        ent = self.tab_view.tab("Enterprise")
        self.ent_login_frame = ctk.CTkFrame(ent); self.ent_login_frame.pack(pady=50)
        ctk.CTkLabel(self.ent_login_frame, text="Enterprise Portal", font=("Roboto", 20, "bold")).pack(pady=20)
        self.org_entry = ctk.CTkEntry(self.ent_login_frame, placeholder_text="Org Name"); self.org_entry.pack(pady=5)
        self.cac_entry = ctk.CTkEntry(self.ent_login_frame, placeholder_text="CAC Number"); self.cac_entry.pack(pady=5)
        self.role_menu = ctk.CTkOptionMenu(self.ent_login_frame, values=["Admin", "Analyst", "Auditor"]); self.role_menu.pack(pady=10)
        ctk.CTkButton(self.ent_login_frame, text="Secure Login", command=self.enterprise_login).pack(pady=20)
        self.ent_login_status = ctk.CTkLabel(self.ent_login_frame, text="", text_color="red"); self.ent_login_status.pack()
        self.ent_dashboard = ctk.CTkFrame(ent, fg_color="transparent")

        # --- SETTINGS ---
        settings_tab = self.tab_view.tab("Settings")
        settings_tab.grid_columnconfigure(0, weight=1); settings_tab.grid_columnconfigure(1, weight=1)
        health_frame = ctk.CTkFrame(settings_tab)
        health_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=20, pady=10)
        ctk.CTkLabel(health_frame, text="SYSTEM HEALTH & TELEMETRY", font=("Roboto", 14, "bold")).pack(anchor="w", padx=10, pady=5)
        self.bars = {}
        for metric in ["Engine Load", "Memory Usage", "Network Latency"]:
            f = ctk.CTkFrame(health_frame, fg_color="transparent"); f.pack(fill="x", padx=10, pady=2)
            ctk.CTkLabel(f, text=metric, width=100, anchor="w").pack(side="left")
            bar = ctk.CTkProgressBar(f, width=400, progress_color="#00FF00"); bar.set(0.1); bar.pack(side="right", expand=True, fill="x")
            self.bars[metric] = bar
        
        config_frame = ctk.CTkFrame(settings_tab)
        config_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)
        ctk.CTkLabel(config_frame, text="CONFIGURATION", font=("Roboto", 14, "bold")).pack(anchor="w", padx=10, pady=5)
        self.auto_var = ctk.StringVar(value="off")
        ctk.CTkSwitch(config_frame, text="Automated Intelligence", command=self.toggle_automation, variable=self.auto_var, onvalue="on", offvalue="off").pack(pady=10, anchor="w", padx=10)
        
        action_frame = ctk.CTkFrame(settings_tab)
        action_frame.grid(row=1, column=1, sticky="nsew", padx=20, pady=10)
        ctk.CTkLabel(action_frame, text="OPERATIONS", font=("Roboto", 14, "bold")).pack(anchor="w", padx=10, pady=5)
        ctk.CTkButton(action_frame, text="📜 Regulatory Contacts", fg_color="gray", command=self.show_regulatory_info).pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(action_frame, text="📄 Generate Audit Report", command=self.generate_report).pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(action_frame, text="🗑️ PURGE DATABASE", fg_color="#4a1919", hover_color="red", command=self.wipe_data).pack(fill="x", padx=10, pady=20)
        self.report_status = ctk.CTkLabel(action_frame, text="")
        self.report_status.pack()

        log_frame = ctk.CTkFrame(settings_tab)
        log_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=20, pady=10)
        ctk.CTkLabel(log_frame, text="LIVE EXECUTION LOG", font=("Roboto", 14, "bold")).pack(anchor="w", padx=10, pady=5)
        self.log_console = ctk.CTkTextbox(log_frame, height=150, font=("Consolas", 11), fg_color="black", text_color="#00FF00")
        self.log_console.pack(fill="both", expand=True, padx=5, pady=5)
        self.log_system_event("System Initialized.")

        # Status Bar
        self.status_bar = ctk.CTkFrame(self.app_frame, height=30, fg_color="#111111"); self.status_bar.grid(row=1, column=0, sticky="ew")
        self.create_status_indicator("🔒 Encryption: AES-256", "green", 0)
        self.create_status_indicator("🇳🇬 Data Residency: Local", "green", 1)

    # --- EXPERT SYSTEM METHODS ---
    def animate_system_health(self):
        while self.running:
            time.sleep(1)
            try:
                self.bars["Engine Load"].set(random.uniform(0.1, 0.4))
                self.bars["Memory Usage"].set(random.uniform(0.2, 0.5))
            except: pass

    def log_system_event(self, message):
        ts = datetime.now().strftime("%H:%M:%S")
        try: self.log_console.insert("end", f"[{ts}] INFO: {message}\n"); self.log_console.see("end")
        except: pass

    # --- HELPER METHODS ---
    def toggle_theme(self):
        if ctk.get_appearance_mode() == "Dark": ctk.set_appearance_mode("Light")
        else: ctk.set_appearance_mode("Dark")
        self.log_system_event("Theme toggled.")

    def create_status_indicator(self, text, color, col_idx):
        ctk.CTkLabel(self.status_bar, text=text, text_color=color, font=("Arial", 11)).pack(side="left", padx=20)

    def create_metric_card(self, parent, title, value, color, col_idx):
        card = ctk.CTkFrame(parent); card.grid(row=0, column=col_idx, padx=10, pady=10, sticky="ew")
        parent.grid_columnconfigure(col_idx, weight=1)
        ctk.CTkLabel(card, text=title, font=("Arial", 12)).pack(pady=(10,0))
        lbl = ctk.CTkLabel(card, text=value, font=("Arial", 20, "bold"), text_color=color); lbl.pack(pady=(0,10))
        self.metric_labels[title] = lbl

    def create_threat_card(self, parent, title, value, color, col):
        card = ctk.CTkFrame(parent, fg_color="#1A1A1A", border_width=1, border_color="gray")
        card.grid(row=0, column=col, padx=5, pady=5, sticky="ew")
        parent.grid_columnconfigure(col, weight=1)
        ctk.CTkLabel(card, text=title, font=("Arial", 12, "bold"), text_color="gray").pack(pady=(10,0))
        lbl = ctk.CTkLabel(card, text=value, font=("Arial", 16, "bold"), text_color=color); lbl.pack(pady=(0,10))
        return lbl

    def refresh_dashboard_data(self):
        score, status, color = get_security_posture_score()
        try:
            self.metric_labels["Security Score"].configure(text=f"{score}/100", text_color=color)
            self.metric_labels["System Status"].configure(text=status, text_color=color)
        except: pass
        dates, counts = get_activity_data_last_7_days()
        self.plot_dynamic_graph(dates, counts)
        self.log_system_event("Dashboard analytics refreshed.")

    def plot_dynamic_graph(self, dates, counts):
        for w in self.graph_frame.winfo_children(): w.destroy()
        fig = Figure(figsize=(6, 3), dpi=100, facecolor="#2B2B2B")
        ax = fig.add_subplot(111); ax.set_facecolor("#2B2B2B")
        ax.plot(dates, counts, marker='o', color='#3B8ED0', linewidth=2)
        ax.fill_between(dates, counts, color='#3B8ED0', alpha=0.3)
        ax.set_title("Activity Log (Last 7 Days)", color="white")
        ax.tick_params(colors='white'); ax.spines['bottom'].set_color('white'); ax.spines['left'].set_color('white')
        ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
        canvas = FigureCanvasTkAgg(fig, master=self.graph_frame); canvas.draw(); canvas.get_tk_widget().pack(fill="both", expand=True)

    def plot_ent_traffic(self, parent, labels, data_in, data_out):
        fig = Figure(figsize=(4, 3), dpi=80, facecolor="#2B2B2B")
        ax = fig.add_subplot(111); ax.set_facecolor("#2B2B2B")
        ax.plot(labels, data_in, color='#00FF00', label="Inbound")
        ax.plot(labels, data_out, color='#3B8ED0', label="Outbound")
        ax.set_title("Network Traffic", color="white", fontsize=10); ax.tick_params(colors='white', labelsize=8)
        ax.legend(facecolor="#2B2B2B", labelcolor="white", fontsize=8)
        ax.spines['bottom'].set_color('white'); ax.spines['left'].set_color('white'); ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
        canvas = FigureCanvasTkAgg(fig, master=parent); canvas.draw(); canvas.get_tk_widget().pack(fill="both", expand=True)

    def plot_ent_threats(self, parent, threat_data):
        fig = Figure(figsize=(4, 3), dpi=80, facecolor="#2B2B2B")
        ax = fig.add_subplot(111); ax.set_facecolor("#2B2B2B")
        ax.bar(list(threat_data.keys()), list(threat_data.values()), color=['#FF5555', '#FFAA00', '#3B8ED0', '#00FF00'])
        ax.set_title("Active Threat Vectors", color="white", fontsize=10); ax.tick_params(colors='white', labelsize=8)
        ax.spines['bottom'].set_color('white'); ax.spines['left'].set_color('white'); ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
        canvas = FigureCanvasTkAgg(fig, master=parent); canvas.draw(); canvas.get_tk_widget().pack(fill="both", expand=True)

    # --- THREAD-SAFE WRAPPERS ---
    def start_scan_thread(self):
        if not self.consent_var.get(): self.scan_status.set("⚠️ Consent Required."); return
        self.scan_status.set("Scanning..."); self.progress_bar.pack(pady=5); self.progress_bar.start()
        self.log_system_event("Network Scan Initiated.")
        threading.Thread(target=self.run_scanner_and_update_ui, daemon=True).start()

    def run_scanner_and_update_ui(self):
        try:
            results = run_network_scan()
            self.after(0, lambda: self.display_results(results))
        except Exception as e: self.scan_status.set(f"Error: {e}")

    def display_results(self, results):
        self.progress_bar.stop(); self.progress_bar.pack_forget()
        self.scan_status.set(f"Found {len(results)} items.")
        self.scan_results_textbox.delete("1.0", "end")
        self.scan_results_textbox.insert("end", "> SCAN COMPLETE.\n> ANALYSIS REPORT:\n\n", "header")
        for res in results:
            tag = "low_risk"
            if "High" in str(res.risk_level): tag = "high_risk"
            elif "Medium" in str(res.risk_level): tag = "medium_risk"
            icon = "[!]" if "High" in str(res.risk_level) else "[+]"
            self.scan_results_textbox.insert("end", f"{icon} IP: {res.target_ip} | Port: {res.port_id}\n", tag)
            self.scan_results_textbox.insert("end", f"    {res.version}\n\n", "remediation")
        self.log_system_event(f"Scan finished. {len(results)} assets identified.")
        self.refresh_dashboard_data()

    def start_web_scan(self):
        url = self.web_url.get().strip()
        if not url: self.web_status.set("Please enter URL"); return
        self.web_status.set(f"Scanning {url}...")
        self.web_results.delete("1.0", "end")
        self.web_results.insert("end", f"> INITIALIZING HTTP SCAN: {url}\n", "info")
        self.log_system_event(f"Web Scan: {url}")
        threading.Thread(target=self.run_web_scan, args=(url,), daemon=True).start()

    def run_web_scan(self, url):
        from modules.web_scanner import scan_website
        results = scan_website(url)
        self.after(0, lambda: self.display_web_results(results))

    def display_web_results(self, results):
        self.web_status.set("Scan Complete")
        for risk, title, desc in results:
            tag = "info"
            if "Critical" in risk: tag = "crit"
            elif "High" in risk: tag = "crit"
            elif "Medium" in risk: tag = "warn"
            elif "Low" in risk: tag = "safe"
            
            self.web_results.insert("end", f"[{risk}] {title}\n", tag)
            self.web_results.insert("end", f"    {desc}\n\n")
        self.log_system_event("Web Scan Completed.")

    def check_breach_thread(self):
        email = self.email_entry.get().strip()
        if email: 
            self.log_system_event(f"Checking breaches for: {email}")
            threading.Thread(target=self.run_breach_check, args=(email,), daemon=True).start()

    def run_breach_check(self, email):
        found, msg, advice, sev = check_email_for_breaches(email)
        self.after(0, lambda: self.update_breach_ui_safe(found, msg, advice, sev, email))

    def update_breach_ui_safe(self, found, msg, advice, sev, email):
        if found:
            self.status_card.configure(fg_color="#4a1919")
            self.lbl_status_icon.configure(text="🚨")
            self.lbl_status_title.configure(text=f"COMPROMISED", text_color="#FF5555")
            self.lbl_status_desc.configure(text=f"Risk: {sev}")
            self.log_system_event(f"ALERT: {email} found in breaches!")
        else:
            self.status_card.configure(fg_color="#153e1b")
            self.lbl_status_icon.configure(text="✅")
            self.lbl_status_title.configure(text="SECURE", text_color="#00FF00")
            self.lbl_status_desc.configure(text="No leaks found.")
            self.log_system_event(f"Analysis clean for {email}")

        self.breach_history_textbox.delete("1.0", "end")
        tag = "crit" if found else "safe"
        self.breach_history_textbox.insert("end", f"ANALYSIS REPORT: {email}\n{msg}\n\n", tag)
        if found:
            self.breach_history_textbox.insert("end", "MITIGATION STEPS:\n", "step")
            self.breach_history_textbox.insert("end", advice, "step")
        
        self.update_breach_history_ui(append=True)
        self.refresh_dashboard_data()

    def toggle_email_monitoring(self):
        status = self.monitor_var.get()
        email = self.email_entry.get().strip()
        if status == "on":
            if not email: self.monitor_switch.deselect(); return
            self.auto_engine.start_engine(email)
            self.lbl_status_desc.configure(text=f"Active Monitoring ON for {email}")
            self.log_system_event(f"Background monitoring engine started for {email}")
        else:
            self.auto_engine.stop_engine()
            self.lbl_status_desc.configure(text="Active Monitoring Paused.")
            self.log_system_event("Background monitoring stopped.")

    def update_breach_history_ui(self, append=False):
        history = get_breach_history()
        if not append: self.breach_history_textbox.delete("1.0", "end")
        for alert in history:
            self.breach_history_textbox.insert("end", f"[{alert.timestamp.strftime('%d/%m %H:%M')}] {alert.breach_name}\n")

    def run_dns_audit(self):
        if not self.dns_consent_var.get(): self.dns_mitigation_box.insert("end", "Consent Required\n", "warn"); return
        domain = self.dns_entry.get().strip()
        if domain:
            self.dns_mitigation_box.delete("1.0", "end"); self.dns_mitigation_box.insert("end", f"> AUDITING: {domain}...\n", "safe"); self.update()
            self.log_system_event(f"DNS Audit: {domain}")
            result = check_domain_security(domain)
            stats = result['status_map']
            def get_col(s): return "#00FF00" if "SECURE" in s else ("#FF5555" if "MISSING" in s else "#FFAA00")
            self.card_spf.configure(text=stats["SPF"], text_color=get_col(stats["SPF"]))
            self.card_dmarc.configure(text=stats["DMARC"], text_color=get_col(stats["DMARC"]))
            self.card_dnssec.configure(text=stats["DNSSEC"], text_color=get_col(stats["DNSSEC"]))
            lat = int(stats["LATENCY"].replace("ms","")) if "ms" in stats["LATENCY"] else 999
            self.card_latency.configure(text=stats["LATENCY"], text_color="#00FF00" if lat<200 else "#FF5555")
            self.dns_mitigation_box.insert("end", f"> SCORE: {result['score']}/100\n", "header")
            for fix in result['mitigations']: self.dns_mitigation_box.insert("end", f"\n{fix}\n", "fix")

    def enterprise_login(self):
        org = self.org_entry.get(); cac = self.cac_entry.get(); role = self.role_menu.get()
        success, msg = authenticate_organization(org, cac, role)
        if success:
            self.ent_login_frame.pack_forget(); self.build_enterprise_dashboard(org, role)
            self.ent_dashboard.pack(fill="both", expand=True, padx=10, pady=10)
            self.log_system_event(f"SOC Login: {role} @ {org}")
        else: self.ent_login_status.configure(text=msg)

    def enterprise_logout(self):
        for w in self.ent_dashboard.winfo_children(): w.destroy()
        self.ent_dashboard.pack_forget(); self.ent_login_frame.pack(pady=50)
        self.org_entry.delete(0, 'end'); self.ent_login_status.configure(text="Session Ended.", text_color="green")
        self.log_system_event("Enterprise Session Closed.")

    def build_enterprise_dashboard(self, org_name, role):
        data = get_enterprise_dashboard_data(org_name)
        head = ctk.CTkFrame(self.ent_dashboard, fg_color="transparent"); head.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(head, text=f"🏢 {org_name.upper()} SOC", font=("Roboto", 24, "bold")).pack(side="left")
        ctk.CTkButton(head, text="LOGOUT", fg_color="#4a1919", width=100, command=self.enterprise_logout).pack(side="right")
        
        viz = ctk.CTkFrame(self.ent_dashboard, fg_color="transparent"); viz.pack(fill="x", pady=10, expand=True)
        viz.grid_columnconfigure(0, weight=1); viz.grid_columnconfigure(1, weight=1)
        g1 = ctk.CTkFrame(viz); g1.grid(row=0, column=0, padx=(0,5), sticky="nsew")
        self.plot_ent_traffic(g1, data['traffic_labels'], data['traffic_in'], data['traffic_out'])
        g2 = ctk.CTkFrame(viz); g2.grid(row=0, column=1, padx=(5,0), sticky="nsew")
        self.plot_ent_threats(g2, data['threat_stats'])

        ctk.CTkLabel(self.ent_dashboard, text="🔴 LIVE ASSET STATUS", font=("Roboto", 14, "bold"), text_color="gray").pack(anchor="w", pady=(10,5))
        tbl = ctk.CTkFrame(self.ent_dashboard); tbl.pack(fill="both", expand=True)
        for i, c in enumerate(["Asset", "IP", "Uptime", "Status"]): ctk.CTkLabel(tbl, text=c, font=("Arial", 12, "bold")).grid(row=0, column=i, padx=20, pady=5, sticky="w")
        for i, item in enumerate(data['fleet']):
            r = i+1
            ctk.CTkLabel(tbl, text=item['name']).grid(row=r, column=0, padx=20, pady=2, sticky="w")
            ctk.CTkLabel(tbl, text=item['ip']).grid(row=r, column=1, padx=20, pady=2, sticky="w")
            ctk.CTkLabel(tbl, text=item['uptime']).grid(row=r, column=2, padx=20, pady=2, sticky="w")
            ctk.CTkButton(tbl, text=item['status'], fg_color=item['color'], width=90, height=22, state="disabled").grid(row=r, column=3, padx=20, pady=2, sticky="w")

    def generate_report(self):
        f, _ = generate_compliance_report()
        if self.report_status: self.report_status.configure(text=f"Saved: {f}", text_color="green")
        os.system(f"start {f}")
        self.log_system_event(f"Report generated: {f}")

    def wipe_data(self):
        clear_all_data()
        if self.report_status: self.report_status.configure(text="Data Wiped", text_color="orange")
        self.update_breach_history_ui()
        self.log_system_event("CRITICAL: Database purged.")
        
    def toggle_automation(self):
        if self.auto_var.get() == "on":
            self.auto_engine.start_engine(self.email_entry.get())
            self.log_system_event("Automation Engine STARTED.")
        else:
            self.auto_engine.stop_engine()
            self.log_system_event("Automation Engine STOPPED.")

    def show_regulatory_info(self):
        info = ctk.CTkToplevel(self); info.geometry("500x400"); info.title("Compliance")
        lbl = ctk.CTkLabel(info, text="REGULATORY CONTACTS\n\n1. NITDA: registrations@nitda.gov.ng\n2. NDPC: compliance@ndpc.gov.ng\nData Sovereignty: Local.", justify="left", padx=20, pady=20, font=("Courier", 12))
        lbl.pack(fill="both", expand=True)