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

# Deterministic Remediation Playbook
# Static, reviewed mitigation templates by port and service. Commands are illustrative examples
# for authorized administrators and are never dynamically interpolated with untrusted input.
REMEDIATION_PLAYBOOK = {
    21: {
        "summary": "FTP may transmit credentials and files in unencrypted cleartext. Migrate to secure protocols such as SFTP (SSH File Transfer Protocol on port 22) or FTPS (FTP over TLS).",
        "steps": [
            "1. Migrate existing users and scheduled batch jobs to SFTP (port 22).",
            "2. Stop and disable legacy FTP service daemons.",
            "3. Enforce perimeter and host firewall rules blocking inbound TCP port 21."
        ],
        "platform": {
            "linux": [
                "sudo systemctl stop vsftpd",
                "sudo systemctl disable vsftpd",
                "sudo ufw deny 21/tcp"
            ],
            "windows": [
                "Stop-Service ftpsvc -WarningAction SilentlyContinue",
                "Set-Service ftpsvc -StartupType Disabled",
                'netsh advfirewall firewall add rule name="Aegis-Block-FTP" dir=in action=block protocol=TCP localport=21'
            ],
            "firewall": [
                "sudo ufw deny 21/tcp"
            ]
        },
        "verification": "nmap -p 21 <authorized-target>",
        "warnings": "Halting the FTP daemon terminates active file transfers. Confirm all client integrations have transitioned to SFTP before disabling the service."
    },
    22: {
        "summary": "SSH is open for remote administration. Do not disable SSH if it is your primary management interface. Instead, enforce key-based authentication, disable root password login, and restrict access to trusted networks.",
        "steps": [
            "1. Generate and deploy SSH Ed25519 or RSA-4096 key pairs for authorized administrators.",
            "2. In /etc/ssh/sshd_config, configure 'PasswordAuthentication no' and 'PermitRootLogin prohibit-password'.",
            "3. Reload sshd and restrict inbound TCP port 22 to trusted bastion/VPN IPs."
        ],
        "platform": {
            "linux": [
                "# In /etc/ssh/sshd_config: PasswordAuthentication no",
                "sudo systemctl reload sshd",
                "sudo ufw allow from <trusted-management-ip> to any port 22 proto tcp"
            ],
            "windows": [
                'netsh advfirewall firewall add rule name="Aegis-Restrict-SSH" dir=in action=allow protocol=TCP localport=22 remoteip=<trusted-management-ip>'
            ],
            "firewall": [
                "sudo ufw allow from <trusted-management-ip> to any port 22 proto tcp"
            ]
        },
        "verification": "ssh -i <private-key> user@<authorized-target>",
        "warnings": "Always verify key-based authentication in a separate active shell session before disabling password authentication or reloading the SSH daemon to avoid administrative lockout."
    },
    23: {
        "summary": "Telnet transmits all session data and administrative credentials in unencrypted plaintext. Disable Telnet and enforce SSH for remote terminal management.",
        "steps": [
            "1. Verify SSH service is operational as the secure replacement for terminal access.",
            "2. Stop and disable the Telnet service daemon and socket.",
            "3. Block TCP port 23 at host and network firewalls."
        ],
        "platform": {
            "linux": [
                "sudo systemctl stop telnet.socket",
                "sudo systemctl disable telnet.socket",
                "sudo ufw deny 23/tcp"
            ],
            "windows": [
                "Disable-WindowsOptionalFeature -Online -FeatureName Telnet-Client",
                'netsh advfirewall firewall add rule name="Aegis-Block-Telnet" dir=in action=block protocol=TCP localport=23'
            ],
            "firewall": [
                "sudo ufw deny 23/tcp"
            ]
        },
        "verification": "nmap -p 23 <authorized-target>",
        "warnings": "Ensure alternative management access (SSH or out-of-band console) is fully operational before disabling Telnet."
    },
    80: {
        "summary": "HTTP web server is open. Plaintext HTTP traffic can be intercepted. Implement automatic HTTP to HTTPS 301 redirects and enforce TLS.",
        "steps": [
            "1. Deploy trusted TLS certificates on the web server (e.g. via Let's Encrypt or corporate PKI).",
            "2. Configure web server with HTTP 301 permanent redirects to HTTPS (port 443).",
            "3. Enable HTTP Strict Transport Security (HSTS) headers."
        ],
        "platform": {
            "linux": [
                "# In Nginx server block: return 301 https://$host$request_uri;",
                "sudo certbot --nginx -d <authorized-target>",
                "sudo systemctl reload nginx"
            ],
            "windows": [
                "# In IIS Manager: URL Rewrite -> Add Rule -> Redirect HTTP to HTTPS",
                'netsh advfirewall firewall add rule name="Aegis-Allow-HTTP" dir=in action=allow protocol=TCP localport=80'
            ],
            "firewall": [
                "sudo ufw allow 80/tcp"
            ]
        },
        "verification": "curl -I http://<authorized-target>",
        "warnings": "An open web port is not automatically a vulnerability. Port 80 is often kept open to serve automatic redirects to HTTPS port 443. Ensure no sensitive endpoints or credentials are submitted over HTTP."
    },
    135: {
        "summary": "Microsoft RPC endpoint mapper is exposed. MSRPC exposes internal Windows services and interface identifiers to network reconnaissance.",
        "steps": [
            "1. Determine if remote administrative RPC is required across this network segment.",
            "2. Restrict port 135 to domain controllers and trusted administrative subnets only.",
            "3. Block MSRPC at perimeter firewalls."
        ],
        "platform": {
            "linux": [
                "sudo ufw deny 135/tcp"
            ],
            "windows": [
                'netsh advfirewall firewall add rule name="Aegis-Block-RPC" dir=in action=block protocol=TCP localport=135'
            ],
            "firewall": [
                "sudo ufw deny 135/tcp"
            ]
        },
        "verification": "nmap -p 135 <authorized-target>",
        "warnings": "Blocking MSRPC between domain members and domain controllers can disrupt Active Directory group policies and remote management tools."
    },
    443: {
        "summary": "HTTPS web server is open with TLS encryption. Maintain current TLS certificate validity, disable legacy SSL/TLS 1.0/1.1 protocols, and enable modern forward-secrecy cipher suites.",
        "steps": [
            "1. Verify that valid, unexpired TLS certificates are deployed.",
            "2. Disable legacy protocols SSLv2, SSLv3, TLS 1.0, and TLS 1.1.",
            "3. Enforce TLS 1.2 and TLS 1.3 with forward-secrecy cipher suites."
        ],
        "platform": {
            "linux": [
                "# Test TLS configuration: testssl.sh https://<authorized-target>",
                "sudo certbot renew --dry-run"
            ],
            "windows": [
                "# In PowerShell, enforce modern TLS protocols",
                "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13"
            ],
            "firewall": [
                "sudo ufw allow 443/tcp"
            ]
        },
        "verification": "curl -I https://<authorized-target>",
        "warnings": "Disabling legacy cipher suites may prevent very old client browsers or embedded devices from connecting."
    },
    445: {
        "summary": "SMB (Server Message Block) file sharing is exposed. Exposed SMB is high risk for lateral movement, credential theft, and wormable exploits (e.g. EternalBlue). Restrict to trusted internal networks.",
        "steps": [
            "1. Disable legacy SMBv1 protocol across all endpoints.",
            "2. Block TCP port 445 at perimeter firewalls to prevent internet exposure.",
            "3. Restrict internal SMB access to authorized local subnets only."
        ],
        "platform": {
            "linux": [
                "sudo systemctl stop smbd",
                "sudo systemctl disable smbd",
                "sudo ufw deny 445/tcp"
            ],
            "windows": [
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                'netsh advfirewall firewall add rule name="Aegis-Block-SMB" dir=in action=block protocol=TCP localport=445'
            ],
            "firewall": [
                "sudo ufw deny 445/tcp"
            ]
        },
        "verification": "nmap -p 445 <authorized-target>",
        "warnings": "Do not unconditionally disable SMB on file servers or domain controllers where network file sharing and Active Directory authentication are required. Restrict by firewall rather than disabling service components."
    },
    3306: {
        "summary": "MySQL database server is listening on a network socket. Databases should not be directly reachable from untrusted networks. Bind to localhost (127.0.0.1) or restrict access strictly to application tiers.",
        "steps": [
            "1. Bind MySQL to loopback interface (127.0.0.1) if only accessed locally.",
            "2. If accessed by remote application servers, restrict access strictly to application IP addresses via firewall.",
            "3. Enforce strong passwords and TLS for all database user accounts."
        ],
        "platform": {
            "linux": [
                "# In /etc/mysql/my.cnf under [mysqld]: bind-address = 127.0.0.1",
                "sudo systemctl restart mysql",
                "sudo ufw allow from <app-server-ip> to any port 3306 proto tcp"
            ],
            "windows": [
                "# In my.ini under [mysqld]: bind-address = 127.0.0.1",
                'netsh advfirewall firewall add rule name="Aegis-Block-MySQL" dir=in action=block protocol=TCP localport=3306'
            ],
            "firewall": [
                "sudo ufw allow from <app-server-ip> to any port 3306 proto tcp"
            ]
        },
        "verification": "nmap -p 3306 <authorized-target>",
        "warnings": "Binding to localhost will prevent all remote application servers from connecting unless routed over an SSH tunnel or VPN."
    },
    3389: {
        "summary": "Remote Desktop Protocol (RDP) is exposed. RDP endpoints are primary targets for ransomware crews and automated credential brute force. Place RDP behind a VPN and enforce Network Level Authentication (NLA).",
        "steps": [
            "1. Place RDP behind a secure VPN gateway or Remote Desktop Gateway.",
            "2. Enforce Network Level Authentication (NLA) on the host.",
            "3. Restrict inbound port 3389 to authorized management IP addresses."
        ],
        "platform": {
            "linux": [
                "sudo systemctl stop xrdp",
                "sudo systemctl disable xrdp",
                "sudo ufw deny 3389/tcp"
            ],
            "windows": [
                '(Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\\cimv2\\terminalservices -Filter "TerminalName=\'RDP-Tcp\'").SetUserAuthenticationRequired(1)',
                'netsh advfirewall firewall add rule name="Aegis-Block-RDP" dir=in action=block protocol=TCP localport=3389'
            ],
            "firewall": [
                "sudo ufw allow from <trusted-management-ip> to any port 3389 proto tcp"
            ]
        },
        "verification": "nmap -p 3389 <authorized-target>",
        "warnings": "Applying firewall rules remotely to block port 3389 will disconnect your current active RDP session. Ensure you have physical console or out-of-band management before applying."
    }
}


def get_remediation_guidance(port: int, service: str = "") -> dict:
    """
    Returns deterministic, conservative remediation guidance for a given port/service.
    Static templates provide example commands for authorized system administrators.
    """
    try:
        port_int = int(port) if port is not None else 0
    except (ValueError, TypeError):
        port_int = 0

    service_str = str(service or "unknown").strip().lower()

    # 1. Check Port Rules First
    if port_int in REMEDIATION_PLAYBOOK:
        data = dict(REMEDIATION_PLAYBOOK[port_int])
        # Tailor Linux command if specific daemon identified
        if port_int == 21 and "vsftpd" not in service_str:
            data = dict(data)
            data["platform"] = dict(data["platform"])
            data["platform"]["linux"] = [
                "sudo systemctl stop ftpd",
                "sudo systemctl disable ftpd",
                "sudo ufw deny 21/tcp"
            ]
        return data

    # 2. Service name fallback
    SERVICE_PORT_MAP = {
        "ftp": 21,
        "ssh": 22,
        "telnet": 23,
        "http": 80,
        "msrpc": 135,
        "https": 443,
        "microsoft-ds": 445,
        "mysql": 3306,
        "rdp": 3389,
        "ms-wbt-server": 3389
    }
    for s_name, mapped_port in SERVICE_PORT_MAP.items():
        if s_name in service_str and mapped_port in REMEDIATION_PLAYBOOK:
            return dict(REMEDIATION_PLAYBOOK[mapped_port])

    # 3. Safe Generic Conservative Fallback
    display_srv = service or "unknown"
    return {
        "summary": f"Verify whether service '{display_srv}' on port {port_int} is required for operational needs. Restrict network exposure using firewall access control lists.",
        "steps": [
            f"1. Identify the application or daemon managing port {port_int} ({display_srv}).",
            "2. If the service is not required, disable or stop the corresponding daemon.",
            f"3. If required, restrict access to authorized management IP addresses."
        ],
        "platform": {
            "linux": [
                f"# Inspect listening process: sudo ss -tulpn | grep ':{port_int}'",
                f"sudo ufw deny {port_int}/tcp"
            ],
            "windows": [
                f"# Inspect listening process: netstat -ano | findstr ':{port_int}'",
                f'netsh advfirewall firewall add rule name="Aegis-Block-Port-{port_int}" dir=in action=block protocol=TCP localport={port_int}'
            ],
            "firewall": [
                f"sudo ufw allow from <trusted-management-ip> to any port {port_int} proto tcp"
            ]
        },
        "verification": f"nmap -p {port_int} <authorized-target>",
        "warnings": f"Verify system dependencies before stopping services on port {port_int}. Unintended service disruption may affect connected applications."
    }


def analyze_port(port, service):
    """
    Classifies the security risk of a given port/service combination and attaches
    deterministic remediation guidance.
    Returns: A dict with keys: port, service, risk, reason, remediation.
    """
    port_int = int(port) if port is not None else None
    service_clean = str(service).lower().strip() if service else ""
    remediation = get_remediation_guidance(port_int, service_clean)

    # 1. Check Port Rules First
    if port_int in RISK_RULES["ports"]:
        risk, reason = RISK_RULES["ports"][port_int]
        return {
            "port": port_int,
            "service": service,
            "risk": risk,
            "reason": reason,
            "remediation": remediation
        }

    # 2. Check Service Name Rules (e.g. if running on non-standard port)
    if service_clean in RISK_RULES["services"]:
        risk, reason = RISK_RULES["services"][service_clean]
        return {
            "port": port_int,
            "service": service,
            "risk": risk,
            "reason": reason,
            "remediation": remediation
        }

    # 3. Default Fallback (Low risk, generic description)
    return {
        "port": port_int,
        "service": service,
        "risk": "LOW",
        "reason": f"Port is open running service '{service or 'unknown'}'. Verify if this service is required to be exposed.",
        "remediation": remediation
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


# Deterministic Security Scoring Model Configuration
SCORE_WEIGHTS = {
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 3
}

SCORING_DISCLAIMER = (
    "Aegis Security Score is a deterministic exposure heuristic based on observed scan findings "
    "and configured weights. It does not measure all security controls or prove exploitability."
)


def get_score_band(score):
    """Maps a numeric security score (0-100) to its descriptive severity band label."""
    if score is None:
        return "UNAVAILABLE"
    score_int = int(score)
    if score_int >= 90:
        return "GOOD"
    elif score_int >= 75:
        return "FAIR"
    elif score_int >= 50:
        return "NEEDS IMPROVEMENT"
    elif score_int >= 25:
        return "POOR"
    else:
        return "CRITICAL"


def calculate_security_score(ports=None, scan_status="success"):
    """
    Computes a deterministic Security Score from 0 to 100 based on unique open port findings.

    Deduction Weights:
      - HIGH:   -25 points
      - MEDIUM: -10 points
      - LOW:    -3 points

    Deduplication Policy:
      Deductions apply once per unique open port finding identified by the composite
      key '{protocol}:{port}' (e.g. 'tcp:80'). Duplicate port rows do not cause duplicate deductions.
      Ports with non-open states (e.g. 'closed', 'filtered') are excluded.

    Failed / Incomplete Scans:
      Returns an unavailable score structure with available=False and score=None.
    """
    if str(scan_status).lower() != "success":
        return {
            "available": False,
            "score": None,
            "max_score": 100,
            "label": "UNAVAILABLE",
            "method": "deterministic_exposure_heuristic",
            "weights": dict(SCORE_WEIGHTS),
            "base_score": 100,
            "total_deduction": 0,
            "deductions": [],
            "disclaimer": SCORING_DISCLAIMER,
            "reason": "Security score is unavailable because the scan was incomplete or failed."
        }

    if not ports:
        return {
            "available": True,
            "score": 100,
            "max_score": 100,
            "label": "GOOD",
            "method": "deterministic_exposure_heuristic",
            "weights": dict(SCORE_WEIGHTS),
            "base_score": 100,
            "total_deduction": 0,
            "deductions": [],
            "disclaimer": SCORING_DISCLAIMER,
            "notice": "Zero open TCP listening ports were detected under the scan profile."
        }

    seen_keys = set()
    deductions = []
    total_deduction = 0

    for p in ports:
        if not isinstance(p, dict):
            continue

        port_val = p.get("port")
        if port_val is None:
            continue

        try:
            port_num = int(port_val)
        except (ValueError, TypeError):
            continue

        state_val = str(p.get("state", "open")).lower().strip()
        if state_val != "open":
            continue

        proto_val = str(p.get("protocol", "tcp")).lower().strip() or "tcp"
        unique_key = f"{proto_val}:{port_num}"

        # Prevent double-counting duplicate findings
        if unique_key in seen_keys:
            continue
        seen_keys.add(unique_key)

        risk_level = str(p.get("risk", "LOW")).upper().strip()
        penalty = SCORE_WEIGHTS.get(risk_level, SCORE_WEIGHTS["LOW"])
        total_deduction += penalty

        deductions.append({
            "port": port_num,
            "protocol": proto_val,
            "service": p.get("service") or "unknown",
            "risk": risk_level,
            "points_deducted": penalty,
            "reason": p.get("reason") or f"Port {port_num}/{proto_val} exposed with risk rating {risk_level}."
        })

    raw_score = 100 - total_deduction
    final_score = max(0, min(100, raw_score))
    label = get_score_band(final_score)

    return {
        "available": True,
        "score": final_score,
        "max_score": 100,
        "label": label,
        "method": "deterministic_exposure_heuristic",
        "weights": dict(SCORE_WEIGHTS),
        "base_score": 100,
        "total_deduction": total_deduction,
        "deductions": deductions,
        "disclaimer": SCORING_DISCLAIMER
    }

