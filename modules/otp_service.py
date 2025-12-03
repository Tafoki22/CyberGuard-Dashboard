# modules/otp_service.py
import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ============================================================
# ⚙️ CONFIGURATION (YOU MUST EDIT THIS SECTION)
# ============================================================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# 1. Put the email address you want to SEND FROM here:
SENDER_EMAIL = "cyberguardng.info@gmail.com" 

# 2. Put the 16-char Google App Password here (NOT your normal password):
SENDER_PASSWORD = "wtpb zpox vdid dftr" 
# ============================================================

def generate_otp(length=6):
    """Generates a cryptographically strong numeric OTP."""
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(recipient_email, otp):
    """
    Sends the OTP via Google SMTP using the App Password.
    """
    subject = "CyberGuard Verification Code"
    
    # Professional HTML Email Template
    body = f"""
    <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <div style="max-width: 600px; margin: auto; border: 1px solid #ddd; padding: 20px; border-radius: 10px;">
                <h2 style="color: #2c3e50; text-align: center;">🛡️ CyberGuard Security</h2>
                <p>Hello,</p>
                <p>You requested a verification code to access the CyberGuard Dashboard.</p>
                <div style="text-align: center; margin: 30px 0;">
                    <span style="background-color: #f2f2f2; padding: 15px 30px; font-size: 24px; letter-spacing: 5px; font-weight: bold; border-radius: 5px;">
                        {otp}
                    </span>
                </div>
                <p>This code is valid for 10 minutes. If you did not request this, please ignore this email.</p>
                <hr style="border: 0; border-top: 1px solid #eee;">
                <p style="font-size: 12px; color: #777; text-align: center;">
                    Securing Nigeria's Digital Future.
                </p>
            </div>
        </body>
    </html>
    """

    try:
        # Connect to Gmail Server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls() # Secure the connection
        
        # Login
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        
        # Prepare Email
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))
        
        # Send
        server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())
        server.quit()
        
        return True, f"OTP sent to {recipient_email}"

    except smtplib.SMTPAuthenticationError:
        print("\n[ERROR] Authentication Failed.")
        print("Did you use a normal password? You MUST use a Google App Password.")
        return False, "Error: Invalid Server Credentials."
        
    except Exception as e:
        print(f"\n[ERROR] Could not send email: {e}")
        return False, "Network Error: Could not send OTP."