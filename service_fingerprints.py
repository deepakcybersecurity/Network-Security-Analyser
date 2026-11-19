"""
Aegis Service Fingerprint Knowledge Base
========================================
Static, reviewed educational knowledge base providing context, typical usage,
associated security concerns, historical attack context (with explicit caveats),
public exposure guidance, and authoritative documentation references.

These cards provide educational context and do not establish that a service
is vulnerable merely because its port is open.
"""

from typing import Any, Dict, List, Optional

FINGERPRINT_DISCLAIMER = (
    "Educational Context Notice: Service fingerprint cards provide general protocol "
    "knowledge and defensive guidance. An open port indicates network exposure, not proof "
    "of vulnerability or active exploitability. Detailed patch levels and configurations "
    "must be verified independently."
)

# Static knowledge base keyed by standard port numbers (highest priority)
# and canonical service names
KNOWLEDGE_BASE: Dict[int, Dict[str, Any]] = {
    21: {
        "service_name": "ftp",
        "display_name": "FTP (File Transfer Protocol)",
        "category": "File Transfer",
        "description": (
            "File Transfer Protocol (FTP) is a legacy client-server protocol used to transfer "
            "files between computers over a network."
        ),
        "typical_use": (
            "Legacy bulk file uploads, website file maintenance, and automated data exchange. "
            "Modern environments replace FTP with SSH File Transfer Protocol (SFTP) or FTPS."
        ),
        "common_security_concerns": (
            "Standard FTP transmits authentication credentials (usernames and passwords) and all file "
            "contents in cleartext without transport encryption. Traffic is vulnerable to passive network sniffing "
            "and man-in-the-middle (MitM) interception on untrusted network segments."
        ),
        "associated_attacks": (
            "Credential sniffing on shared networks, brute-force password guessing against user accounts, "
            "and unauthorized anonymous access if anonymous logins are permitted."
        ),
        "public_exposure_guidance": (
            "Direct internet exposure of unencrypted FTP is rarely justified and highly discouraged. "
            "If file transfer capabilities are required, deploy SFTP (port 22) or FTPS (FTP over TLS) "
            "with enforced transport encryption and strict IP allowlisting."
        ),
        "defensive_recommendations": [
            "Decommission legacy FTP daemons and transition all clients to SFTP (SSH File Transfer Protocol).",
            "If FTPS is mandatory, enforce explicit TLS (AUTH TLS) and reject unencrypted cleartext connections.",
            "Disable anonymous access and enforce complex passwords or certificate-based authentication.",
            "Restrict inbound access at host and network firewalls to designated authorized IP ranges."
        ],
        "references": [
            {"title": "IETF RFC 959 — File Transfer Protocol Specification", "url": "https://datatracker.ietf.org/doc/html/rfc959"},
            {"title": "NIST SP 800-123 — Guide to General Server Security", "url": "https://csrc.nist.gov/publications/detail/sp/800-123/final"}
        ],
        "knowledge_limitations": (
            "A standard port scan confirms TCP port 21 is open but does not reveal whether the server "
            "supports explicit TLS (FTPS), whether anonymous logins are permitted, or which FTP daemon is running."
        )
    },
    22: {
        "service_name": "ssh",
        "display_name": "SSH (Secure Shell)",
        "category": "Remote Administration",
        "description": (
            "Secure Shell (SSH) is an encrypted protocol used for secure remote command-line login, "
            "remote command execution, and secure data communications."
        ),
        "typical_use": (
            "Secure remote systems administration for Linux/UNIX servers, network appliances, and "
            "cloud virtual machines. Used for administrative shell sessions, SFTP, and automated CI/CD pipelines."
        ),
        "common_security_concerns": (
            "While the SSH protocol is cryptographically robust, exposed SSH daemons are persistent targets "
            "for automated credential brute-force and dictionary attacks. Weak passwords, exposed root login, "
            "outdated cryptographic algorithms, and unpatched server implementations represent the primary risks."
        ),
        "associated_attacks": (
            "Automated credential stuffing and brute-force dictionary attacks, private key compromise, "
            "and exploitation of outdated SSH implementations when patches are neglected."
        ),
        "public_exposure_guidance": (
            "Direct public exposure should be minimized. Where internet-accessible SSH is necessary for remote "
            "management, it must be hardened with key-based authentication, disabled root login, connection rate "
            "limiting (e.g. fail2ban), or placed behind a VPN gateway / bastion host."
        ),
        "defensive_recommendations": [
            "Enforce public-key authentication (ed25519 or RSA >= 3072-bit) and disable password-based authentication.",
            "Set 'PermitRootLogin no' in sshd_config to prevent direct administrative root logins.",
            "Deploy intrusion prevention tools such as Fail2ban or SSHGuard to mitigate brute-force attempts.",
            "Restrict access using IP allowlisting or require connection through an authorized VPN/bastion host."
        ],
        "references": [
            {"title": "OpenSSH Official Manual and Security Guidelines", "url": "https://www.openssh.com/manual.html"},
            {"title": "IETF RFC 4251 — The Secure Shell (SSH) Protocol Architecture", "url": "https://datatracker.ietf.org/doc/html/rfc4251"}
        ],
        "knowledge_limitations": (
            "An open SSH port does NOT indicate that the server is vulnerable. SSH is designed for secure remote "
            "access; risk depends on configuration (password vs. key auth), access controls, and software patch levels."
        )
    },
    23: {
        "service_name": "telnet",
        "display_name": "Telnet",
        "category": "Remote Administration",
        "description": (
            "Telnet is a legacy protocol from the early internet era providing unencrypted bidirectional "
            "interactive text communications over a virtual terminal connection."
        ),
        "typical_use": (
            "Historically used for remote command-line administration of servers and network hardware. "
            "Completely deprecated in modern networks in favor of SSH."
        ),
        "common_security_concerns": (
            "Telnet transmits all communications — including administrative usernames, passwords, and command "
            "outputs — entirely in cleartext. Anyone with passive eavesdropping access on the network path can capture "
            "privileged credentials."
        ),
        "associated_attacks": (
            "Cleartext credential interception via network packet sniffing, active MitM session hijacking, "
            "and automated botnet credential attacks against default embedded device accounts."
        ),
        "public_exposure_guidance": (
            "Telnet should never be exposed to the public internet or untrusted internal networks under any circumstances. "
            "Decommission Telnet immediately and migrate all administrative tasks to SSH."
        ),
        "defensive_recommendations": [
            "Immediately disable and uninstall the Telnet server daemon (e.g. telnetd) across all endpoints.",
            "Migrate all administrative access to SSH (port 22) with strong encryption.",
            "Block inbound TCP port 23 across all network and host perimeter firewalls."
        ],
        "references": [
            {"title": "IETF RFC 854 — Telnet Protocol Specification", "url": "https://datatracker.ietf.org/doc/html/rfc854"},
            {"title": "NIST SP 800-52 — Guidelines for the Selection and Use of Transport Layer Security", "url": "https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final"}
        ],
        "knowledge_limitations": (
            "A standard port scan confirms TCP port 23 is listening but cannot inspect whether the service "
            "implements local access restrictions or custom authentication."
        )
    },
    80: {
        "service_name": "http",
        "display_name": "HTTP (Hypertext Transfer Protocol)",
        "category": "Web Service",
        "description": (
            "Hypertext Transfer Protocol (HTTP) is the foundational application-layer protocol for distributed, "
            "collaborative, hypermedia information systems and the World Wide Web."
        ),
        "typical_use": (
            "Hosting websites, web applications, and REST APIs. In modern environments, plain HTTP on port 80 "
            "is typically configured solely to issue an immediate HTTP 301/308 redirect to secure HTTPS on port 443."
        ),
        "common_security_concerns": (
            "HTTP lacks transport-layer encryption. Browsers and clients communicate in cleartext, meaning session cookies, "
            "submitted form credentials, and sensitive application data can be intercepted or modified in transit by network attackers."
        ),
        "associated_attacks": (
            "Passive credential and session cookie sniffing, man-in-the-middle (MitM) content injection, "
            "SSL stripping attacks, and web application vulnerabilities (e.g. XSS, SQLi) if applications are hosted directly on HTTP."
        ),
        "public_exposure_guidance": (
            "Public exposure of port 80 is acceptable when configured strictly to redirect inbound traffic to HTTPS (port 443). "
            "Production web applications must never serve authenticated sessions or process sensitive data over plain HTTP."
        ),
        "defensive_recommendations": [
            "Configure the web server (Nginx/Apache/IIS) to redirect all plain HTTP requests to HTTPS with HTTP 301 Permanent Redirect.",
            "Deploy valid SSL/TLS certificates (e.g. Let's Encrypt / automated ACME) on port 443.",
            "Implement HTTP Strict Transport Security (HSTS) headers with appropriate max-age and includeSubDomains directives."
        ],
        "references": [
            {"title": "IETF RFC 7230 — Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing", "url": "https://datatracker.ietf.org/doc/html/rfc7230"},
            {"title": "Mozilla Web Security Guidelines — Server Side TLS and HTTPS", "url": "https://infosec.mozilla.org/guidelines/web_security"}
        ],
        "knowledge_limitations": (
            "An open port 80 is classified as MEDIUM risk by Aegis because traffic is unencrypted; however, this is not proof of an "
            "insecure application if the server's sole behavior is an immediate redirect to HTTPS."
        )
    },
    443: {
        "service_name": "https",
        "display_name": "HTTPS (HTTP Secure / TLS)",
        "category": "Secure Web Service",
        "description": (
            "HTTP Secure (HTTPS) is the encrypted version of HTTP, running over Transport Layer Security (TLS) "
            "to provide confidentiality, data integrity, and server authentication."
        ),
        "typical_use": (
            "Standard secure delivery for web applications, e-commerce, banking, APIs, and modern websites."
        ),
        "common_security_concerns": (
            "While HTTPS encrypts data in transit, encryption alone does not guarantee application security. "
            "Weak TLS configurations (e.g. supporting deprecated TLS 1.0/1.1 or weak ciphers), expired or untrusted certificates, "
            "and underlying web application flaws (e.g. injection, broken access control) remain significant concerns."
        ),
        "associated_attacks": (
            "TLS downgrade attacks if legacy protocols are enabled, certificate spoofing if untrusted authorities are used, "
            "and web application exploits operating transparently over the encrypted tunnel."
        ),
        "public_exposure_guidance": (
            "Public exposure of HTTPS on port 443 is standard and expected for public-facing web services. "
            "Ensure regular certificate renewal and adhere to current cryptographic cipher recommendations."
        ),
        "defensive_recommendations": [
            "Enforce modern TLS protocols (TLS 1.2 and TLS 1.3 only); disable legacy SSLv3, TLS 1.0, and TLS 1.1.",
            "Configure strong cryptographic cipher suites (e.g. ECDHE with AES-GCM or ChaCha20-Poly1305).",
            "Maintain automated certificate renewal to avoid expiration outages.",
            "Deploy a Web Application Firewall (WAF) and maintain security patches on web server software."
        ],
        "references": [
            {"title": "IETF RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3", "url": "https://datatracker.ietf.org/doc/html/rfc8446"},
            {"title": "Mozilla SSL Configuration Generator & Best Practices", "url": "https://ssl-config.mozilla.org/"}
        ],
        "knowledge_limitations": (
            "An open port 443 with valid TLS is considered LOW exposure risk by Aegis, but this does not verify the security "
            "of the web application code, databases, or API logic running behind the HTTPS listener."
        )
    },
    135: {
        "service_name": "msrpc",
        "display_name": "Microsoft RPC (Endpoint Mapper)",
        "category": "Remote Procedure Call",
        "description": (
            "Microsoft Remote Procedure Call (MSRPC) Endpoint Mapper coordinates inter-process communication "
            "and active directory services across Windows operating systems."
        ),
        "typical_use": (
            "Internal Windows administrative communication, DCOM services, Active Directory replication, and "
            "Microsoft Exchange / enterprise infrastructure management."
        ),
        "common_security_concerns": (
            "Exposed MSRPC endpoints allow unauthenticated network attackers to enumerate active RPC services, interfaces, "
            "and internal host details. Historically, MSRPC implementations have been targeted for remote code execution "
            "and active reconnaissance."
        ),
        "associated_attacks": (
            "RPC endpoint enumeration (e.g. using rpcdump/impacket), active directory mapping, and exploitation of "
            "legacy DCOM/RPC buffer vulnerabilities."
        ),
        "public_exposure_guidance": (
            "Microsoft RPC should never be exposed to the public internet. It is intended strictly for protected internal "
            "enterprise network segments and Windows domain members."
        ),
        "defensive_recommendations": [
            "Block inbound TCP port 135 at all perimeter firewalls and internet gateways.",
            "Restrict RPC communication to trusted internal Active Directory management subnets.",
            "Keep the Windows operating system and RPC runtime updated with the latest cumulative security updates."
        ],
        "references": [
            {"title": "Microsoft Learn — How to Configure RPC Dynamic Port Allocation", "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-rpc-dynamic-port-allocation-with-firewalls"},
            {"title": "CISA — Securing Network Infrastructure Devices", "url": "https://www.cisa.gov/news-events/alerts/2018/04/16/russian-state-sponsored-cyber-actors"}
        ],
        "knowledge_limitations": (
            "An open port 135 confirms the RPC endpoint mapper is listening but does not verify whether specific DCOM "
            "sub-services or interfaces are exposed or vulnerable to remote exploits."
        )
    },
    445: {
        "service_name": "microsoft-ds",
        "display_name": "Microsoft Directory Services (SMB)",
        "category": "File Sharing Protocol",
        "description": (
            "Server Message Block (SMB) running over TCP port 445 provides shared access to files, printers, "
            "named pipes, and serial ports between nodes on a Windows network."
        ),
        "typical_use": (
            "Enterprise Windows file shares, administrative remote management (PsExec/WMI), network printing, "
            "and domain controller replication."
        ),
        "common_security_concerns": (
            "Exposing SMB to untrusted networks is a critical security hazard. SMB has historically been a primary vector "
            "for network worm propagation, ransomware distribution, and credential relay attacks. Unauthenticated SMB exposure "
            "can allow unauthorized file access and lateral movement."
        ),
        "associated_attacks": (
            "Historical context: Vulnerabilities such as MS17-010 (EternalBlue) were exploited by malware like WannaCry and NotPetya. "
            "Note: An open port 445 alone does NOT establish that a system is vulnerable to EternalBlue or any exploit; "
            "vulnerability requires unpatched software and specific SMBv1 enablement. Other risks include NTLM credential relaying and SMB brute-forcing."
        ),
        "public_exposure_guidance": (
            "Under no circumstances should SMB port 445 be accessible from the public internet. ISPs and enterprise perimeter "
            "firewalls should universally filter inbound and outbound port 445 traffic."
        ),
        "defensive_recommendations": [
            "Block inbound TCP port 445 at all internet-facing firewalls and edge routers.",
            "Disable legacy SMBv1 protocol entirely across all Windows workstations and servers.",
            "Enforce SMB signing (SMB 3.x) and SMB encryption to prevent relay and tampering attacks.",
            "Require VPN access and multi-factor authentication for remote access to internal file shares."
        ],
        "references": [
            {"title": "Microsoft Learn — Beyond the Edge: How to Secure SMB Traffic", "url": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic"},
            {"title": "CISA Advisory — Securing SMB Networks Against Known Exploits", "url": "https://www.cisa.gov/news-events/alerts/2017/01/16/securing-network-infrastructure"}
        ],
        "knowledge_limitations": (
            "An open port 445 confirms SMB transport is listening. It does NOT prove that EternalBlue or any specific exploit is viable, "
            "as modern Windows systems with SMBv1 disabled and cumulative updates applied are not vulnerable to historical exploits."
        )
    },
    3306: {
        "service_name": "mysql",
        "display_name": "MySQL Database Server",
        "category": "Database Service",
        "description": (
            "MySQL is a widely used open-source relational database management system (RDBMS) designed for structured "
            "data persistence and transactional application support."
        ),
        "typical_use": (
            "Back-end data storage for web applications, enterprise ERPs, content management systems (WordPress/Drupal), "
            "and analytical services."
        ),
        "common_security_concerns": (
            "Exposing database listeners directly to public networks creates a high-value target for automated credential "
            "brute-force attacks, authentication bypass attempts, and potential unauthenticated memory corruption exploits. "
            "Databases contain high-impact organizational data that should never be directly accessible from untrusted zones."
        ),
        "associated_attacks": (
            "Automated database credential brute-forcing (e.g. root account guessing), SQL injection pivoting, "
            "and exploitation of unpatched RDBMS service vulnerabilities."
        ),
        "public_exposure_guidance": (
            "Database servers should never be exposed to public networks. Databases must be bound to localhost (127.0.0.1) "
            "for local application consumption, or placed in a private database subnet accessible only by designated application servers."
        ),
        "defensive_recommendations": [
            "Configure 'bind-address = 127.0.0.1' in my.cnf to restrict connections to the local host.",
            "If remote access is mandatory, restrict access via firewall rules strictly to authorized application server IPs.",
            "Enforce strong authentication passwords, disable anonymous users, and remove remote root login permissions.",
            "Mandate TLS/SSL transport encryption for all remote database connections."
        ],
        "references": [
            {"title": "MySQL 8.0 Reference Manual — General Security Issues and Hardening", "url": "https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html"},
            {"title": "CIS MySQL Benchmark — Center for Internet Security", "url": "https://www.cisecurity.org/benchmark/mysql"}
        ],
        "knowledge_limitations": (
            "An open port 3306 confirms the MySQL port is responsive. It does not prove that credentials are weak, that root login is "
            "permitted remotely, or that unauthorized data access can occur."
        )
    },
    3389: {
        "service_name": "ms-wbt-server",
        "display_name": "RDP (Remote Desktop Protocol)",
        "category": "Remote Administration",
        "description": (
            "Remote Desktop Protocol (RDP) is a proprietary Microsoft protocol providing users and administrators with a graphical "
            "remote interface to connect to Windows desktops and servers."
        ),
        "typical_use": (
            "Remote administrative access, technical support, and remote worker virtual desktop access."
        ),
        "common_security_concerns": (
            "Publicly exposed RDP is one of the most frequently attacked attack surfaces on the internet. Attackers continuously run "
            "automated distributed brute-force campaigns, credential stuffing attacks, and scan for historical vulnerabilities "
            "(e.g. BlueKeep/CVE-2019-0708) to establish initial access and deploy ransomware."
        ),
        "associated_attacks": (
            "Automated RDP credential brute-forcing, password spraying, initial access brokerage for ransomware operators, "
            "and historical vulnerability exploitation (e.g. BlueKeep context; note: open port does not imply vulnerability without proof of missing patches)."
        ),
        "public_exposure_guidance": (
            "Direct internet exposure of RDP is strongly discouraged. RDP should be positioned behind a secure VPN gateway, "
            "a Remote Desktop Gateway with multi-factor authentication, or a zero-trust network access (ZTNA) solution."
        ),
        "defensive_recommendations": [
            "Place RDP access behind a corporate VPN or Remote Desktop Gateway requiring Multi-Factor Authentication (MFA).",
            "Enforce Network Level Authentication (NLA) on the host to require authentication before an RDP session is established.",
            "Implement account lockout policies to thwart brute-force password guessing attacks.",
            "Restrict inbound RDP traffic via perimeter firewalls strictly to designated administrative IP subnets."
        ],
        "references": [
            {"title": "Microsoft Learn — Remote Desktop Security Best Practices", "url": "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-plan-access-from-anywhere"},
            {"title": "CISA Alert — Ongoing Cyber Activity Targeting Remote Desktop Protocol", "url": "https://www.cisa.gov/news-events/alerts/2018/09/27/remote-desktop-protocol"}
        ],
        "knowledge_limitations": (
            "An open port 3389 confirms an RDP listener is active. It does not prove that NLA is disabled, that passwords are weak, "
            "or that the host is susceptible to specific historical exploits like BlueKeep."
        )
    },
    53: {
        "service_name": "domain",
        "display_name": "DNS (Domain Name System)",
        "category": "Name Resolution",
        "description": (
            "Domain Name System (DNS) is the hierarchical and decentralized naming system used to identify computers, "
            "services, and other resources reachable over the internet."
        ),
        "typical_use": (
            "Resolving human-readable hostnames to IP addresses and managing authoritative domain zone records."
        ),
        "common_security_concerns": (
            "Open recursive DNS resolvers can be abused in distributed denial-of-service (DDoS) amplification attacks. "
            "Misconfigured DNS servers may allow unauthorized DNS zone transfers (AXFR), leaking internal network topology."
        ),
        "associated_attacks": (
            "DNS amplification DDoS attacks, unauthorized AXFR zone transfers, DNS cache poisoning, and DNS spoofing."
        ),
        "public_exposure_guidance": (
            "Authoritative DNS servers for registered public domains must be accessible publicly, but recursive resolvers "
            "should strictly restrict querying to local/internal network clients."
        ),
        "defensive_recommendations": [
            "Disable open recursion if the DNS server is publicly accessible.",
            "Restrict AXFR DNS zone transfers to authorized secondary name servers.",
            "Deploy DNSSEC to provide cryptographic origin authentication for DNS data."
        ],
        "references": [
            {"title": "IETF RFC 1035 — Domain Names: Implementation and Specification", "url": "https://datatracker.ietf.org/doc/html/rfc1035"},
            {"title": "CISA — Alert on DNS Amplification Attacks", "url": "https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks"}
        ],
        "knowledge_limitations": (
            "Port 53 TCP is primarily used for zone transfers or large responses; full DNS assessment requires UDP inspection."
        )
    },
    25: {
        "service_name": "smtp",
        "display_name": "SMTP (Simple Mail Transfer Protocol)",
        "category": "Mail Transfer",
        "description": (
            "Simple Mail Transfer Protocol (SMTP) is the standard protocol for email transmission across IP networks."
        ),
        "typical_use": (
            "Mail transfer agent (MTA) server-to-server routing and client email submission."
        ),
        "common_security_concerns": (
            "Misconfigured open mail relays can be hijacked by unauthorized third parties to distribute spam and phishing campaigns. "
            "Cleartext SMTP transmissions risk exposure unless upgraded with STARTTLS."
        ),
        "associated_attacks": (
            "Open mail relay exploitation, spam distribution, user enumeration via VRFY/EXPN, and credential intercept without TLS."
        ),
        "public_exposure_guidance": (
            "Public MTAs legitimately expose port 25 for inbound mail delivery, but relaying must be strictly disabled for external hosts."
        ),
        "defensive_recommendations": [
            "Disable open mail relaying; accept incoming mail only for authorized local recipient domains.",
            "Enforce mandatory STARTTLS with strong modern ciphers.",
            "Deploy SPF, DKIM, and DMARC DNS records to protect domain reputation and prevent spoofing."
        ],
        "references": [
            {"title": "IETF RFC 5321 — Simple Mail Transfer Protocol", "url": "https://datatracker.ietf.org/doc/html/rfc5321"},
            {"title": "M3AAWG Email Security Best Practices", "url": "https://www.m3aawg.org/published-documents"}
        ],
        "knowledge_limitations": (
            "Port 25 exposure does not establish whether the mail server functions as an open relay or enforces STARTTLS."
        )
    }
}

# Service name to port mapping for alias resolution
SERVICE_NAME_MAPPINGS: Dict[str, int] = {
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "dns": 53,
    "http": 80,
    "https": 443,
    "ssl/http": 443,
    "msrpc": 135,
    "epmap": 135,
    "microsoft-ds": 445,
    "smb": 445,
    "mysql": 3306,
    "ms-wbt-server": 3389,
    "rdp": 3389
}


def get_generic_fingerprint(port: Optional[int], service: Optional[str] = None, identification_method: str = "Unclassified") -> Dict[str, Any]:
    """Generates a safe, generic fingerprint card for unknown or unclassified services."""
    p_num = int(port) if port is not None else 0
    clean_srv = str(service).strip() if service else "unknown"
    return {
        "service_name": clean_srv,
        "display_name": f"Unclassified Service (Port {p_num})",
        "category": "Unclassified Network Service",
        "description": (
            f"An active listening socket was detected on port {p_num} (service identifier: '{clean_srv}'). "
            "No specialized signature profile matches this listener in the static Aegis knowledge base."
        ),
        "typical_use": (
            "The specific purpose depends on the host application role and operating system configuration. "
            "Verify the listening process using local administrative tools (e.g. 'ss -tlpn' or 'netstat' on Linux, "
            "or 'Get-NetTCPConnection' on Windows)."
        ),
        "common_security_concerns": (
            "Any unverified listening network service expands the host attack surface. Unrecognized services may "
            "correspond to custom internal tools, debug ports, legacy software, or inadvertently exposed management consoles."
        ),
        "associated_attacks": (
            "General network reconnaissance, banner grabbing, automated port scanning, and potential service probing."
        ),
        "public_exposure_guidance": (
            "Do not expose unclassified ports to public or untrusted networks unless the service has been formally "
            "identified, authorized by security policy, and hardened."
        ),
        "defensive_recommendations": [
            "Identify the specific binary or daemon bound to this port using local administrative commands.",
            "Determine whether network accessibility is strictly required for business operations.",
            "If exposure is not required, terminate the daemon or block the port using host or network firewalls."
        ],
        "references": [
            {"title": "IANA Service Name and Port Number Registry", "url": "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"}
        ],
        "knowledge_limitations": (
            "Aegis did not perform protocol-specific probing on this port. Identification requires local host "
            "inspection or deep service version detection."
        ),
        "identification_method": identification_method,
        "disclaimer": FINGERPRINT_DISCLAIMER
    }


def get_service_fingerprint(
    port: Optional[int],
    service: Optional[str] = None,
    profile_id: str = "quick",
    deterministic_risk: str = "LOW"
) -> Dict[str, Any]:
    """
    Retrieves or generates an educational Service Fingerprint card for a detected port/service.

    Args:
        port: Observed TCP port number (int).
        service: Detected or reported service name (str).
        profile_id: Aegis scan profile used (e.g. 'quick', 'service_detection', 'comprehensive').
        deterministic_risk: Risk rating assigned by deterministic risk analyzer ('HIGH', 'MEDIUM', 'LOW').

    Returns:
        Structured dictionary matching the Service Fingerprint schema.
    """
    port_int = int(port) if port is not None else None
    service_clean = str(service).lower().strip() if service else ""

    # Determine identification method label based on scan profile
    if profile_id in ("service_detection", "comprehensive"):
        ident_method = "Service Version Detection (Nmap Probe)"
    else:
        ident_method = "Inferred from standard port assignment (Service detection disabled)"

    # 1. Match by standard port number first
    entry = None
    if port_int in KNOWLEDGE_BASE:
        entry = dict(KNOWLEDGE_BASE[port_int])
    # 2. Match by normalized service name
    elif service_clean in SERVICE_NAME_MAPPINGS:
        mapped_port = SERVICE_NAME_MAPPINGS[service_clean]
        if mapped_port in KNOWLEDGE_BASE:
            entry = dict(KNOWLEDGE_BASE[mapped_port])

    if entry is None:
        return get_generic_fingerprint(port_int, service_clean, identification_method=ident_method)

    # Attach contextual metadata
    entry["observed_port"] = port_int
    entry["observed_service"] = service or entry["service_name"]
    entry["deterministic_risk"] = deterministic_risk
    entry["identification_method"] = ident_method
    entry["disclaimer"] = FINGERPRINT_DISCLAIMER

    return entry
