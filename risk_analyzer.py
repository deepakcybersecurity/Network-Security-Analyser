# Rule-based educational exposure risk mapping for common ports and services
RISK_RULES = {
    # Port-specific rules (highest priority)
    "ports": {
        21: ("HIGH", "FTP (File Transfer Protocol) is an unencrypted legacy protocol. Credentials and files are transmitted in cleartext, making them vulnerable to network sniffing."),
        23: ("HIGH", "Telnet is an unencrypted legacy protocol. Administrative login credentials and terminal sessions are sent in cleartext."),
        445: ("HIGH", "Microsoft Directory Services (SMB) is exposed over the network. SMB is a high-risk service frequently targeted for lateral movement and remote code execution exploits (e.g. EternalBlue)."),
        3306: ("HIGH", "MySQL database server is directly exposed on the network, presenting a high-value target for unauthorized access and brute-force attempts."),
        3389: ("HIGH", "Remote Desktop Protocol (RDP) is exposed. Exposed RDP services are frequently targeted by automated brute-force attacks and protocol exploits."),
        22: ("MEDIUM", "SSH (Secure Shell) is exposed. Ensure secure key-based authentication is enforced and rate-limiting (like Fail2ban) is enabled to protect the remote management interface."),
        135: ("MEDIUM", "Microsoft RPC (Remote Procedure Call) endpoint mapper is exposed. This service is commonly used for network reconnaissance and active directory mapping."),
        80: ("MEDIUM", "HTTP web server is exposed. Traffic is unencrypted, meaning credentials or session tokens could be intercepted in transit. Consider migrating to HTTPS."),
        443: ("LOW", "HTTPS (HTTP Secure) is exposed. Traffic is encrypted in transit using SSL/TLS, which is the standard secure configuration for web hosting.")
    },
    # Service name-specific rules (fallback)
    "services": {
        "ftp": ("HIGH", "FTP service detected. Credentials and data are transmitted in cleartext, making the service vulnerable to intercept."),
        "telnet": ("HIGH", "Telnet service detected. Sessions are unencrypted, exposing administrative credentials."),
        "mysql": ("HIGH", "MySQL Database service detected. Databases should generally not be exposed directly to public networks."),
        "microsoft-ds": ("HIGH", "Microsoft Directory Services (SMB) detected. Databases or file shares should generally not be exposed directly to public networks."),
        "ms-wbt-server": ("HIGH", "RDP Remote Desktop service detected. RDP should be protected behind a VPN or restricted IP access list."),
        "rdp": ("HIGH", "RDP Remote Desktop service detected. RDP should be protected behind a VPN or restricted IP access list."),
        "ssh": ("MEDIUM", "SSH Remote Management service detected. Review SSH authentication settings and restrict access IP lists."),
        "msrpc": ("MEDIUM", "Microsoft RPC (Remote Procedure Call) service detected. Restrict network access to Windows administrative services."),
        "http": ("MEDIUM", "HTTP Web service detected. Credentials or session identifiers are sent unencrypted. Upgrade to HTTPS."),
        "https": ("LOW", "HTTPS Secure Web service detected. Traffic is encrypted under SSL/TLS."),
        "ssl/http": ("LOW", "HTTPS Secure Web service detected. Traffic is encrypted under SSL/TLS.")
    }
}

def analyze_port(port, service):
    """
    Classifies the security risk of a given port/service combination.
    This provides a basic educational exposure risk assessment.
    Returns: A dict with keys: port, service, risk, reason.
    """
    port = int(port) if port is not None else None
    service_clean = str(service).lower().strip() if service else ""

    # 1. Check Port Rules First
    if port in RISK_RULES["ports"]:
        risk, reason = RISK_RULES["ports"][port]
        return {
            "port": port,
            "service": service,
            "risk": risk,
            "reason": reason
        }

    # 2. Check Service Name Rules (e.g. if running on non-standard port)
    if service_clean in RISK_RULES["services"]:
        risk, reason = RISK_RULES["services"][service_clean]
        return {
            "port": port,
            "service": service,
            "risk": risk,
            "reason": reason
        }

    # 3. Default Fallback (Low risk, generic description)
    return {
        "port": port,
        "service": service,
        "risk": "LOW",
        "reason": f"Port is open running service '{service or 'unknown'}'. Verify if this service is required to be exposed."
    }

def calculate_overall_risk(ports_analysis):
    """
    Calculates the overall scan risk based on individual port findings.
    Rules:
    - If any HIGH finding exists -> HIGH
    - Else if any MEDIUM finding exists -> MEDIUM
    - Else -> LOW
    """
    if not ports_analysis:
        return "LOW"

    risks = [item["risk"] for item in ports_analysis]
    
    if "HIGH" in risks:
        return "HIGH"
    elif "MEDIUM" in risks:
        return "MEDIUM"
    else:
        return "LOW"
