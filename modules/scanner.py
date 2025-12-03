# modules/scanner.py
import os
import socket
import threading
from database.models import ScanResult
from database.db_session import create_session
from modules.cloud_sync import sync_scan_to_cloud

# --- 1. OFFLINE CVE DATABASE (The "What") ---
CVE_DATABASE = {
    445: "CVE-2017-0144 (EternalBlue) - Critical Ransomware Risk",
    3389: "CVE-2019-0708 (BlueKeep) - Remote Desktop Exploit",
    8080: "Misconfigured Web Proxy - High Risk for ISP Routers",
    23: "Cleartext Telnet - Credential Theft Risk",
    21: "FTP Anonymous Login - Data Leakage Risk",
    135: "RPC DCOM Exploit - Legacy Windows Vulnerability",
    5555: "ADB Interface Exposed - Android Device Risk"
}

# --- 2. MITIGATION DATABASE (The "How") ---
# Professional remediation steps for a Cyber Security Student
MITIGATION_DB = {
    445: "ACTION: Disable SMBv1 immediately. Run PowerShell: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false'. Ensure Patch MS17-010 is installed.",
    3389: "ACTION: Disable RDP if not in use. If required, use a VPN gateway, enforce NLA (Network Level Authentication), and change default port.",
    8080: "ACTION: Check Router Administration page. Disable 'Remote Management' and change default Admin/Admin credentials immediately.",
    23: "ACTION: Kill Telnet service. Switch to SSH (Port 22) which uses encryption. Telnet transmits passwords in plain text.",
    21: "ACTION: Disable Anonymous Authentication in your FTP server config. Enforce FTPS (SSL/TLS).",
    135: "ACTION: Block TCP 135 at the firewall level. This RPC port is a common target for lateral movement.",
    5555: "ACTION: Turn off 'USB Debugging' on the Android device connected to this network.",
    "DEFAULT": "ACTION: If this service is not required for business operations, stop the service and close the port via Windows Firewall."
}

POS_PORTS = [8580, 8080, 8000, 2000] 

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3389: "RDP",
    8080: "HTTP-Proxy", 8580: "POS-Terminal", 5555: "ADB"
}

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((ip, port))
        if port in [80, 8080]: s.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner[:30] 
    except:
        return ""

def scan_port(ip, port, results_list):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5) 
        result = sock.connect_ex((ip, port))
        
        if result == 0: 
            service = COMMON_PORTS.get(port, "Unknown")
            banner = grab_banner(ip, port)
            
            # Risk Logic
            risk = "🟢 Low"
            details = "Standard Service"
            mitigation = MITIGATION_DB.get("DEFAULT") # Default advice

            if port in CVE_DATABASE:
                risk = "🔴 High"
                details = f"ALERT: {CVE_DATABASE[port]}"
                mitigation = MITIGATION_DB.get(port, mitigation)
            
            elif port in POS_PORTS:
                risk = "🟡 Medium"
                details = "Potential POS System"
                mitigation = "ACTION: Ensure this POS terminal is on a segmented VLAN separate from guest Wi-Fi."
            
            elif port in [22, 23, 3389]:
                risk = "🔴 High"
                details = "Remote Access Service Exposed"
                mitigation = MITIGATION_DB.get(port, mitigation)

            # Store result object with mitigation advice embedded in 'version' for MVP simplicity
            # Or we can append it to details
            full_details = f"{details}\n    🛡️ {mitigation}"

            scan_res = ScanResult(
                target_ip=ip,
                port_id=port,
                protocol='TCP',
                service_name=service,
                version=full_details, # Storing mitigation here for display
                state="Open",
                risk_level=risk
            )
            results_list.append(scan_res)
        sock.close()
    except:
        pass

def run_network_scan():
    """
    Orchestrates the scan and syncs critical threats to the Cloud.
    """
    print("Starting Cloud-Connected Network Scan...")
    
    local_ip = get_local_ip()
    target_ips = [local_ip, "127.0.0.1"] 
    base_ip = ".".join(local_ip.split('.')[:3])
    target_ips.append(f"{base_ip}.1")

    found_results = []
    threads = []
    
    # Threading for performance
    for ip in target_ips:
        for port in COMMON_PORTS.keys():
            t = threading.Thread(target=scan_port, args=(ip, port, found_results))
            threads.append(t)
            t.start()
            
    for t in threads:
        t.join()

    # Save to Local Database
    session = create_session()
    for res in found_results:
        db_clone = ScanResult(
            target_ip=res.target_ip,
            port_id=res.port_id,
            protocol=res.protocol,
            service_name=res.service_name,
            version=res.version,
            state=res.state,
            risk_level=res.risk_level
        )
        session.add(db_clone)
    session.commit()
    session.close()

    # --- ☁️ CLOUD SYNC LOGIC ---
    # REPLACE THIS with the API Key you found in pgAdmin!
   # ✅ CORRECT
    API_KEY = ("CYBERGUARD_API_KEY", "PLACEHOLDER_KEY_FOR_GITHUB")

    
    if found_results:
        print(f"--- Analysis Complete. Checking for Cloud Sync candidates... ---")

    for res in found_results:
        # Only send High/Critical risks to the cloud
        if "High" in str(res.risk_level):
            print(f"🚀 Syncing Critical Threat to Cloud: {res.target_ip}")
            sync_scan_to_cloud(
                api_key=API_KEY,
                device_name=f"Desktop-Client-{local_ip}",
                ip=res.target_ip,
                threat_level="CRITICAL",
                details=f"Port {res.port_id} Open ({res.service_name}) - {res.version}"
            )

    return found_results