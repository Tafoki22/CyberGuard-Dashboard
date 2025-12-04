# modules/license.py
import requests
import platform
import uuid
import os
import json

# ⚠️ REPLACE WITH YOUR LIVE RENDER URL
CLOUD_URL = "https://cyberguard-api.onrender.com"
LICENSE_FILE = "license.key"

def get_hardware_id():
    """Generates a unique fingerprint for this computer."""
    return str(uuid.getnode())

def get_device_name():
    return platform.node()

# --- FILE PERSISTENCE ---
def save_license_file(api_key):
    """Saves the API Key to a local file for future runs."""
    try:
        with open(LICENSE_FILE, "w") as f:
            f.write(api_key.strip())
        return True
    except:
        return False

def load_license_file():
    """Reads the API Key from the local file if it exists."""
    if os.path.exists(LICENSE_FILE):
        try:
            with open(LICENSE_FILE, "r") as f:
                return f.read().strip()
        except:
            return None
    return None

# --- SERVER COMMUNICATION ---
def get_org_info_from_key(api_key):
    """
    Validates the Key and retrieves the Organization Name from the Cloud.
    Used for Auto-Activation.
    """
    try:
        # We reuse the dashboard endpoint because it validates the key and returns org_name
        response = requests.get(
            f"{CLOUD_URL}/api/v1/dashboard/{api_key}",
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            return True, data.get("org_name", "Unknown Org")
        else:
            return False, None
    except:
        return False, None

def verify_org_license(org_name, api_key):
    """Manual Activation Check."""
    try:
        response = requests.post(
            f"{CLOUD_URL}/api/v1/activate",
            json={"name": org_name, "api_key": api_key},
            timeout=10
        )
        if response.status_code == 200:
            # If valid, save the file automatically!
            save_license_file(api_key)
            return True, response.json()['message']
        else:
            return False, response.json().get('detail', "Verification Failed")
    except requests.exceptions.RequestException:
        return False, "Connection Error"

def notify_server_login(org_name, api_key, email):
    """Device Handshake & Kill Switch Check."""
    hw_id = get_hardware_id()
    device = get_device_name()
    
    payload = {
        "org_name": org_name,
        "api_key": api_key,
        "user_email": email,
        "device_name": device,
        "hw_id": hw_id
    }
    
    try:
        response = requests.post(
            f"{CLOUD_URL}/api/v1/register/device",
            json=payload,
            timeout=10
        )
        if response.status_code == 200:
            return True, "Access Granted"
        elif response.status_code == 403:
            return False, "⛔ BLOCKED: This device is banned."
        else:
            return False, f"Server Error: {response.text}"
    except:
        return True, "⚠️ Offline Mode"