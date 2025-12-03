# 🛡️ CyberGuard Dashboard: Nigeria's Sovereign Digital Defense Platform

**S-VCG Grant Edition (v1.1)**

CyberGuard is a privacy-first, offline-capable cybersecurity platform designed specifically for the Nigerian digital ecosystem. Unlike generic global tools, CyberGuard is engineered for **Data Sovereignty**, **Infrastructural Resilience**, and **NDPR Compliance**.

![Status](https://img.shields.io/badge/Status-Stable-green)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![License](https://img.shields.io/badge/License-MIT-orange)

---

## 🚀 Key Features

### 1. 🔐 Identity & Access Management (IAM)
- **Secure Authentication:** 2-Step Verification with Email OTP (One-Time Password) for all registrations and password resets.
- **Role-Based Access Control (RBAC):** Distinct login flows for Admins, Analysts, and Auditors.

### 2. 🌐 Network Vulnerability Scanner (Offline)
- Detects high-risk open ports (SMB, RDP, Telnet) using native sockets (No Nmap required).
- Includes a **Local CVE Database** tailored to threats prevalent in Nigerian SMEs (e.g., EternalBlue).
- **Compliance:** Enforces mandatory "Cybercrimes Act 2015" consent verification before scanning.
- **Mitigation Engine:** Provides actionable remediation steps (e.g., PowerShell commands) for identified risks.

### 3. 🕷️ Web Vulnerability Scanner (VulnaScan Core)
- **New Feature:** Integrated DAST (Dynamic Application Security Testing) engine.
- Scans websites for **SQL Injection**, **XSS**, and missing security headers (CSP, HSTS).
- Features "Error-Based Detection" logic to minimize false positives.

### 4. 👤 Privacy-Preserving Breach Monitor
- Checks credentials against global breach databases using **k-Anonymity** (SHA-1 Hashing).
- Provides actionable recovery guidance specific to the **Nigerian Banking Ecosystem** (BVN/NIN alerts).
- **Real-Time Monitor:** Toggle switch to enable continuous background monitoring for a specific email.

### 5. 🏛️ DNS Security Auditor
- Validates **SPF**, **DKIM**, and **DMARC** records to prevent Business Email Compromise (BEC).
- **CNII Detection:** Automatically flags `.gov.ng` domains as Critical National Information Infrastructure.
- **QoS Check:** Measures latency against **NCC Technical Standard 132** (<200ms).
- **Threat Matrix:** Visualizes DNS health with a 4-point status dashboard.

### 6. 🏢 Enterprise SOC Platform
- Simulates a localized Security Operations Center (SOC) for banks and agencies.
- **Real-Time Telemetry:** Visualizes network traffic and threat distribution using dynamic graphs.
- **Asset Tracking:** Monitors the health status of fleet devices (Routers, POS Terminals).
- **Compliance Scorecard:** Auto-calculates NDPR/CBN compliance levels.

### 7. ⚙️ Expert System & Telemetry
- **Live Console:** Displays internal system events and logs in real-time (Matrix style).
- **System Health:** Monitors engine load and memory usage.
- **Automated Intelligence:** Background daemon runs scans every 6 hours with an **Ethical Opt-Out** switch (NDPR Article 7).

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.10 or higher
- Windows 10/11

### Setup for Developers
```bash
# 1. Clone the repository
git clone [https://github.com/TAFOKI22/CyberGuard.git](https://github.com/TAFOKI22/CyberGuard.git)

# 2. Create Virtual Environment
python -m venv venv
.\venv\Scripts\activate

# 3. Install Dependencies
pip install -r requirements.txt

# 4. Run the Application
python main.py