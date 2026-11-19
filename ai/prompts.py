"""Prompt definitions and schema templates for Aegis AI Security Analyst."""

SYSTEM_PROMPT = """You are Aegis AI Security Analyst, an automated network exposure and security assessment assistant for authorized cybersecurity assessments.

You analyze completed TCP port scan results produced by Aegis Scanner and provide clear, professional, actionable security guidance.

CRITICAL INSTRUCTIONS & CONSTRAINTS:
1. DETERMINISTIC RISK PRESERVATION (MANDATORY):
   You MUST PRESERVE the exact risk classifications determined by Aegis (HIGH, MEDIUM, LOW) for each port and service.
   You must NEVER downgrade or upgrade an existing finding's risk level. If Aegis determined FTP is HIGH risk, it MUST remain HIGH.
2. NO HALLUCINATIONS:
   You must ONLY analyze the open ports, services, and protocols present in the provided scan data.
   Do NOT assume, invent, or speculate on open ports, unobserved services, unverified CVEs, or active exploits.
3. STRUCTURED JSON OUTPUT ONLY:
   Respond with a single valid JSON object adhering strictly to the schema below without any markdown fences, conversational prefix, or trailing text.

JSON Schema:
{
  "summary": "Concise executive-level summary of the target host's overall network exposure and risk posture.",
  "findings": [
    {
      "port": 21,
      "service": "ftp",
      "aegis_risk": "HIGH",
      "why_it_matters": "Clear, accessible explanation of why this service is exposed.",
      "security_concern": "Specific network security risk (e.g. credential sniffing, unauthorized lateral movement, unencrypted transmission)."
    }
  ],
  "recommendations": [
    "Prioritized, numbered remediation step 1...",
    "Prioritized, numbered remediation step 2..."
  ],
  "beginner_explanation": "An intuitive, plain-English explanation or analogy explaining what these findings mean to a non-specialist or student.",
  "verification_steps": [
    "Run 'nmap -p <port> <target>' to verify the port is closed or filtered after remediation.",
    "..."
  ]
}
"""


def build_user_prompt(scan_data: dict) -> str:
    """Builds a sanitized, structured context prompt from scan results."""
    target = scan_data.get("target", "unknown")
    overall_risk = scan_data.get("overall_risk", "LOW")
    ports = scan_data.get("ports", [])
    profile_info = scan_data.get("scan_profile", {})
    profile_name = profile_info.get("name", "TCP Scan")

    if not ports:
        return (
            f"Target Host: {target}\n"
            f"Scan Profile: {profile_name}\n"
            f"Aegis Overall Risk: {overall_risk}\n"
            f"Open Ports: None discovered (0 open ports).\n\n"
            "Generate the security assessment confirming the target's strong perimeter posture, "
            "with recommendations for maintaining defensive hygiene."
        )

    lines = [
        f"Target Host: {target}",
        f"Scan Profile: {profile_name}",
        f"Aegis Overall Risk: {overall_risk}",
        f"Discovered Open Ports ({len(ports)}):",
    ]

    for p in ports:
        lines.append(
            f"- Port {p.get('port')}/{p.get('protocol', 'tcp')} ({p.get('state', 'open')}): "
            f"Service='{p.get('service', 'unknown')}', "
            f"Aegis Risk={p.get('risk', 'LOW')}, "
            f"Reason='{p.get('reason', '')}'"
        )

    lines.append(
        "\nProvide a comprehensive, professional security assessment matching the JSON schema. "
        "Strictly preserve each finding's Aegis Risk."
    )
    return "\n".join(lines)


def build_offline_fallback_assessment(scan_data: dict) -> dict:
    """Provides a deterministic, expert-crafted security assessment when offline

    or when no OpenAI API key is configured. Ensures Aegis delivers full value
    under all circumstances without failing or returning empty states.
    """
    target = scan_data.get("target", "127.0.0.1")
    overall_risk = scan_data.get("overall_risk", "LOW")
    ports = scan_data.get("ports", [])

    if not ports:
        return {
            "summary": (
                f"The assessment for {target} revealed zero open TCP ports within the scanned profile. "
                "The target host exhibits strong perimeter filtering or minimal surface exposure."
            ),
            "findings": [],
            "recommendations": [
                "1. Maintain current host-level and network firewall configurations.",
                "2. Conduct periodic egress and UDP exposure assessments to verify comprehensive perimeter defense.",
                "3. Ensure administrative remote access services remain restricted to internal VPN tunnels.",
            ],
            "beginner_explanation": (
                "Think of the scanned computer as a house where all exterior doors and windows are closed "
                "and locked. Potential visitors cannot see inside or enter through common entryways."
            ),
            "verification_steps": [
                f"Run 'nmap -sT -F {target}' periodically to detect any newly opened listening sockets.",
                f"Verify firewall rules with 'iptables -L -n -v' or 'netsh advfirewall firewall show rule name=all'.",
            ],
            "_model": "aegis-expert-heuristic (offline mode)",
        }

    findings = []
    recs = []
    verification = []

    high_ports = [p for p in ports if p.get("risk") == "HIGH"]
    med_ports = [p for p in ports if p.get("risk") == "MEDIUM"]
    low_ports = [p for p in ports if p.get("risk") == "LOW"]

    for idx, p in enumerate(ports, start=1):
        port_num = p.get("port")
        service = p.get("service", "unknown")
        risk = p.get("risk", "LOW")
        reason = p.get("reason", "Open network service.")

        why_it_matters = reason
        concern = (
            f"Service '{service}' on port {port_num} exposes a potential entry point for unauthorized probing."
        )
        if risk == "HIGH":
            concern = (
                f"High-risk exposure on port {port_num} ({service}) may allow credential interception, "
                "unauthenticated protocol exploits, or lateral movement."
            )
        elif risk == "MEDIUM":
            concern = (
                f"Exposing port {port_num} ({service}) provides network reconnaissance data and an administrative surface."
            )

        findings.append({
            "port": int(port_num),
            "service": service,
            "aegis_risk": risk,
            "why_it_matters": why_it_matters,
            "security_concern": concern,
        })

    # Build prioritized recommendations
    rec_counter = 1
    if high_ports:
        for hp in high_ports:
            p_num = hp.get("port")
            p_srv = hp.get("service")
            recs.append(
                f"{rec_counter}. Critical: Restrict or disable {p_srv} (port {p_num}). "
                "If required internally, bind to localhost or place behind a secure VPN gateway."
            )
            verification.append(f"Run 'nmap -p {p_num} {target}' to confirm the port is closed or filtered.")
            rec_counter += 1

    if med_ports:
        for mp in med_ports:
            p_num = mp.get("port")
            p_srv = mp.get("service")
            if p_num == 22 or p_srv == "ssh":
                recs.append(
                    f"{rec_counter}. Restrict SSH (port 22): Enforce key-based authentication, "
                    "disable root login, and deploy Fail2ban rate-limiting."
                )
            elif p_num == 80 or p_srv == "http":
                recs.append(
                    f"{rec_counter}. Migrate HTTP (port 80) to HTTPS (port 443) with valid TLS certificates "
                    "and enable HSTS redirection headers."
                )
            else:
                recs.append(
                    f"{rec_counter}. Audit exposure for service '{p_srv}' (port {p_num}) and restrict incoming IPs via firewall."
                )
            verification.append(f"Run 'nmap -p {p_num} {target}' to verify firewall rule enforcement.")
            rec_counter += 1

    if low_ports and not recs:
        recs.append(
            f"{rec_counter}. Maintain encrypted standards for observed low-risk services (e.g. TLS certificates and cipher suites)."
        )
        verification.append(f"Run 'nmap -p {low_ports[0].get('port')} {target}' to audit service banners.")

    summary = (
        f"Aegis assessed target {target} and discovered {len(ports)} open TCP listening socket(s) "
        f"resulting in an overall {overall_risk} risk posture. "
        f"Identified findings include {len(high_ports)} HIGH, {len(med_ports)} MEDIUM, and {len(low_ports)} LOW risk services. "
        f"{'Immediate perimeter remediation is recommended for high-priority exposures.' if high_ports else 'The observed exposure appears manageable with standard service hardening.'}"
    )

    beginner_explanation = (
        f"Imagine {target} is a building with {len(ports)} unlocked doors. "
        f"Some doors (like high-risk ports) allow anyone passing by to attempt entry or listen in on conversations. "
        "The best security practice is to close and lock any doors that are not actively required for business operations."
    )

    return {
        "summary": summary,
        "findings": findings,
        "recommendations": recs,
        "beginner_explanation": beginner_explanation,
        "verification_steps": verification if verification else [f"Run 'nmap -sT -F {target}' to confirm overall baseline."],
        "_model": "aegis-expert-heuristic (offline mode)",
    }
