# modules/enterprise.py
import re
import random
from datetime import datetime, timedelta

def authenticate_organization(org_name, cac_number, role="Admin"):
    """
    Validates Business Identity and Role.
    """
    # 1. Basic Validation
    if len(org_name) < 3: return False, "Org Name too short."
    
    # 2. CAC Validation
    # Regex for RC (Registered Company) or BN (Business Name)
    pattern = r'^(RC|BN|IT)\d{4,9}$'
    if not re.match(pattern, cac_number.upper()):
        return False, "Invalid CAC. Use RC123456."

    # 3. Role Confirmation (Simulation)
    return True, f"Welcome, {role} of {org_name}."

def get_enterprise_dashboard_data(org_name):
    """
    Generates data for the 'Real-Time' SOC Graphs.
    Used by the Expert Edition Dashboard.
    """
    # 1. Traffic Data (Line Chart)
    times = [(datetime.now() - timedelta(hours=x)).strftime('%H:00') for x in range(8)]
    times.reverse()
    inbound_traffic = [random.randint(100, 500) for _ in range(8)]
    outbound_traffic = [random.randint(80, 400) for _ in range(8)]

    # 2. Threat Distribution (Pie Chart Data)
    threats = {
        "Phishing": random.randint(10, 40),
        "Malware": random.randint(5, 20),
        "DDoS": random.randint(0, 5),
        "Policy": random.randint(10, 30)
    }

    # 3. Fleet Status
    device_types = ["Core Router", "HR Server", "Finance DB", "CEO Laptop", "Guest Wi-Fi"]
    fleet = []
    for dev in device_types:
        status = random.choice(["Secure", "Secure", "Warning", "Critical"])
        color = "#00FF00" if status == "Secure" else ("#FFAA00" if status == "Warning" else "#FF5555")
        fleet.append({
            "name": dev,
            "ip": f"10.0.5.{random.randint(10, 99)}",
            "status": status,
            "color": color,
            "uptime": f"{random.randint(1, 30)}d"
        })

    # Return the dictionary structure expected by ui/dashboard.py
    return {
        "traffic_labels": times,
        "traffic_in": inbound_traffic,
        "traffic_out": outbound_traffic,
        "threat_stats": threats,
        "fleet": fleet,
        "compliance": random.randint(85, 100)
    }