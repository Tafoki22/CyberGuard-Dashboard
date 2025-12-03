# modules/email_check.py
import hashlib
import requests
import datetime
from database.models import BreachAlert
from database.db_session import create_session

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

# --- PROFESSIONAL MITIGATION PLAYBOOKS ---
PLAYBOOK_BUSINESS = [
    "⚠️ IMMEDIATE: Contact your IT Security Administrator.",
    "1. Reset Password via internal Active Directory or Identity Provider.",
    "2. Audit Mail Forwarding Rules: Hackers often auto-forward emails to themselves.",
    "3. Revoke Session Tokens: Sign out of all devices (Office 365 / Google Workspace).",
    "4. Check 'Sent Items' for phishing emails sent from your account.",
    "5. Enforce Hardware MFA (YubiKey) or App-based 2FA."
]

PLAYBOOK_PERSONAL = [
    "1. Change Password immediately using a Password Manager.",
    "2. Enable 2FA (Two-Factor Authentication) on this account.",
    "3. Check linked Financial Apps (Kuda, Opay, GTB) if they use this email.",
    "4. Verify Recovery Email/Phone Number has not been changed.",
    "5. Check for 'New Login' alerts in your inbox history."
]

def check_email_for_breaches(email: str):
    """
    Checks an email against global breach databases using k-anonymity.
    Returns: (found, count, risk_level, mitigation_steps)
    """
    encoded_email = email.lower().encode('utf-8')
    sha1_hash = hashlib.sha1(encoded_email).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    try:
        response = requests.get(HIBP_API_URL + prefix, timeout=10)
        
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    count = int(count)
                    severity = "CRITICAL" if count > 5 else "HIGH"
                    
                    # Determine context based on domain
                    domain = email.split('@')[-1]
                    is_business = domain not in ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
                    steps = PLAYBOOK_BUSINESS if is_business else PLAYBOOK_PERSONAL
                    
                    save_breach_alert(email, count)
                    return True, count, severity, steps

        elif response.status_code == 404:
            pass 
            
    except requests.exceptions.RequestException:
        return False, 0, "ERROR", ["Check Internet Connection."]
        
    return False, 0, "SAFE", ["Your account appears secure.", "Continue practicing good hygiene (Unique Passwords)."]

def save_breach_alert(email, count):
    session = create_session()
    masked_email = email[:3] + "****" + email.split('@')[-1]
    alert = BreachAlert(
        email_hash=masked_email, 
        breach_name=f"Global Database Hit (Count: {count})",
        pwned_date=datetime.datetime.utcnow(),
        data_classes="Credentials",
        is_acknowledged=False
    )
    session.add(alert)
    session.commit()
    session.close()

def get_breach_history():
    session = create_session()
    alerts = session.query(BreachAlert).order_by(BreachAlert.timestamp.desc()).all()
    session.close()
    return alerts