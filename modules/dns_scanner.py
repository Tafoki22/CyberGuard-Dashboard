# modules/dns_scanner.py
import dns.resolver
import time
from datetime import datetime

def check_domain_security(domain):
        # FORCE GOOGLE DNS (Fixes "ERR" on local networks)
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4'] 
        dns.resolver.override_system_resolver(resolver) # Apply globally
        

# --- MITIGATION KNOWLEDGE BASE ---
MITIGATION_PLAYBOOK = {
    "SPF_MISSING": "⚠️ ACTION: Create a TXT record for the domain.\n   Syntax: 'v=spf1 mx -all'\n   Impact: Prevents attackers from sending emails from your domain.",
    "DMARC_MISSING": "⚠️ ACTION: Deploy DMARC to monitor email traffic.\n   Start with: 'v=DMARC1; p=none; rua=mailto:admin@domain.com'\n   Impact: Provides visibility into spoofing attempts.",
    "DMARC_WEAK": "⚠️ ACTION: Elevate DMARC policy to 'Quarantine' or 'Reject'.\n   Current policy 'None' offers zero protection against active attacks.",
    "DNSSEC_MISSING": "⚠️ ACTION: Enable DNSSEC at your Domain Registrar.\n   Impact: Prevents DNS Cache Poisoning and Man-in-the-Middle redirection attacks.",
    "LATENCY_HIGH": "⚠️ ACTION: Migrate to an Anycast DNS Provider (Cloudflare/AWS).\n   Current latency violates NCC QoS standards (<200ms)."
}

DNS_CACHE = {}

def get_cached_result(domain):
    if domain in DNS_CACHE:
        timestamp, data = DNS_CACHE[domain]
        if (datetime.now() - timestamp).total_seconds() < 3600:
            return data
    return None

def check_domain_security(domain):
    # FORCE GOOGLE DNS (Fixes "ERR" on local networks)
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4'] 
        dns.resolver.override_system_resolver(resolver)
    except:
        pass

    cached = get_cached_result(domain)
    if cached: return cached

    findings = []
    mitigations = []
    score = 100
    
    # Clean domain
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip()
    
    # Trackers for the UI Cards
    status_map = {
        "SPF": "UNKNOWN",
        "DMARC": "UNKNOWN",
        "DNSSEC": "UNKNOWN",
        "LATENCY": "0ms"
    }

    # --- 1. NCC LATENCY CHECK ---
    try:
        start_time = time.time()
        dns.resolver.resolve(domain, 'A')
        latency = (time.time() - start_time) * 1000
        status_map["LATENCY"] = f"{int(latency)}ms"
        
        if latency > 200:
            score -= 10
            findings.append("❌ High DNS Latency (NCC Violation)")
            mitigations.append(MITIGATION_PLAYBOOK["LATENCY_HIGH"])
    except:
        status_map["LATENCY"] = "ERR"
        score -= 20

    # --- 2. SPF CHECK ---
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_found = False
        for rdata in answers:
            if "v=spf1" in rdata.to_text():
                spf_found = True
                status_map["SPF"] = "SECURE"
                break
        if not spf_found:
            score -= 30
            status_map["SPF"] = "MISSING"
            mitigations.append(MITIGATION_PLAYBOOK["SPF_MISSING"])
    except:
        status_map["SPF"] = "MISSING"
        score -= 30
        mitigations.append(MITIGATION_PLAYBOOK["SPF_MISSING"])

    # --- 3. DMARC CHECK ---
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarc_found = False
        for rdata in answers:
            txt = rdata.to_text()
            if "v=DMARC1" in txt:
                dmarc_found = True
                if "p=reject" in txt or "p=quarantine" in txt:
                    status_map["DMARC"] = "SECURE"
                else:
                    status_map["DMARC"] = "WEAK"
                    score -= 10
                    mitigations.append(MITIGATION_PLAYBOOK["DMARC_WEAK"])
                break
        if not dmarc_found:
            status_map["DMARC"] = "MISSING"
            score -= 30
            mitigations.append(MITIGATION_PLAYBOOK["DMARC_MISSING"])
    except:
        status_map["DMARC"] = "MISSING"
        score -= 30
        mitigations.append(MITIGATION_PLAYBOOK["DMARC_MISSING"])

    # --- 4. DNSSEC CHECK ---
    try:
        dns.resolver.resolve(domain, 'DNSKEY')
        status_map["DNSSEC"] = "SECURE"
    except:
        status_map["DNSSEC"] = "MISSING"
        score -= 20
        mitigations.append(MITIGATION_PLAYBOOK["DNSSEC_MISSING"])

    # Final Result
    rating = "WEAK"
    color = "red"
    if score >= 90: rating, color = "SECURE", "green"
    elif score >= 50: rating, color = "MODERATE", "orange"

    result = {
        "domain": domain,
        "score": score,
        "rating": rating,
        "color": color,
        "status_map": status_map,
        "mitigations": mitigations
    }
    
    DNS_CACHE[domain] = (datetime.now(), result)
    return result