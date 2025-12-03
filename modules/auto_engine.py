# modules/auto_engine.py
import time
import logging
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from plyer import notification

# Import Core Modules
from modules.scanner import run_network_scan
from modules.email_check import check_email_for_breaches

# Setup Local Audit Logging (Transparency Requirement)
logging.basicConfig(
    filename='automation_audit.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(message)s'
)

class AutomatedEngine:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.is_running = False
        self.monitored_email = None
        
    def start_engine(self, email=None):
        """
        Activates the 6-hour background loop.
        NDPR Article 7 Compliance: Must be explicitly triggered by user.
        """
        if self.is_running:
            return
            
        self.monitored_email = email
        
        # Schedule the job (Every 6 hours = 360 minutes)
        self.scheduler.add_job(self.perform_risk_assessment, 'interval', hours=6, id='auto_scan')
        self.scheduler.start()
        self.is_running = True
        
        logging.info("ENGINE START: User activated background monitoring.")
        self.send_notification(
            "CyberGuard Activated", 
            "I don wake up! I go verify your security every 6 hours."
        )

    def stop_engine(self):
        """
        Stops all background processes immediately (Right to Opt-Out).
        """
        if self.is_running:
            self.scheduler.shutdown(wait=False)
            self.is_running = False
            logging.info("ENGINE STOP: User deactivated background monitoring.")
            self.send_notification("CyberGuard Paused", "No wahala. Background monitoring don stop.")

    def perform_risk_assessment(self):
        """
        The Predictive Risk Engine.
        Combines Network + Email data to assess total threat level.
        """
        logging.info("SCAN STARTED: Running scheduled risk assessment...")
        
        # 1. Network Scan
        net_results = run_network_scan()
        open_high_risk_ports = [r for r in net_results if "High" in str(r.risk_level)]
        
        # 2. Email Check (if enabled)
        email_compromised = False
        if self.monitored_email:
            found, _, _, severity = check_email_for_breaches(self.monitored_email)
            if found and severity in ["HIGH", "CRITICAL"]:
                email_compromised = True

        # 3. Predictive Risk Scoring (Compound Risk)
        # If you have High Risk Ports AND a Pwned Email, you are a prime target.
        if open_high_risk_ports and email_compromised:
            self.send_notification(
                "🚨 CRITICAL DANGER ALERT", 
                "Omo! Your Network AND Email dey exposed. Hackers fit enter easily. Open App NOW!"
            )
            logging.warning("RISK: CRITICAL (Compound Threat Detected)")
            
        elif open_high_risk_ports:
            count = len(open_high_risk_ports)
            self.send_notification(
                f"⚠️ Network Alert: {count} Risks", 
                f"We see {count} dangerous ports open. E fit be Ransomware risk."
            )
            logging.warning(f"RISK: HIGH ({count} open ports)")
            
        elif email_compromised:
            self.send_notification(
                "🔐 Data Breach Alert", 
                "Your email don cast inside new database dump. Change password sharp sharp."
            )
            logging.warning("RISK: HIGH (Credential Leak)")
            
        else:
            logging.info("RISK: LOW (System appears secure)")
            # Optional: Send "All Clear" notification once a day, not every 6 hours (to avoid annoyance)

    def send_notification(self, title, message):
        """
        Uses Plyer to send native OS notifications.
        """
        try:
            notification.notify(
                title=title,
                message=message,
                app_name="CyberGuard Nigeria",
                timeout=12
            )
        except Exception as e:
            logging.error(f"NOTIFICATION FAILURE: {e}")