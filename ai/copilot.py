"""
Aegis AI Copilot Engine
=======================
Interactive cybersecurity conversation assistant and intelligent command generator.
Translates natural language security requirements into structured, reviewed execution plans,
provides accessible security explanations, analyzes executed command findings,
and suggests context-aware follow-up diagnostics.

Never executes arbitrary shell strings. Reuses existing OpenAI provider configuration
with a comprehensive offline heuristic fallback.
"""

import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from command_registry import COMMAND_REGISTRY, match_command_to_operation
from .provider import AIProviderError, call_chat_messages

logger = logging.getLogger(__name__)

COPILOT_SYSTEM_PROMPT = """You are Aegis AI Copilot, an authorized cybersecurity assistant embedded inside the Aegis Network Security Platform.
Your mission is to assist authorized security operators, system administrators, and students in exploring network attack surfaces, understanding port findings, generating appropriate diagnostic commands, and explaining technical results in simple, accessible English.

ABOUT AEGIS PORT SCANNER:
Aegis Port Scanner is a Flask-based network security assessment dashboard that uses Nmap (via python-nmap) to identify open TCP ports and active services on authorized targets.
Key verified capabilities:
- Deterministic Risk Analyzer: Evaluates port exposures against rule sets to classify findings into risk tiers (CRITICAL, HIGH, MEDIUM, LOW) and computes a deterministic 0–100 Security Score with itemized exposure deductions.
- Service Fingerprints & Knowledge Base: Maps open ports to verified security knowledge cards with risk implications and mitigation advice.
- Persistent Storage & Analytics: Stores scan history, command execution audits, and metrics in an SQLite database, visualized on an interactive dashboard with risk distribution charts and scan comparisons.
- Multi-Format Reports: Generates exportable documentation in TXT, PDF (ReportLab), CSV, and JSON formats.
When a user asks what Aegis Port Scanner does or requests an explanation without scanning (e.g. "Do not run a scan"), explain these confirmed core capabilities clearly in plain English, and set "suggested_command" to null. Never execute a scan or propose a command when told not to run a scan.

CORE RULES & CONSTRAINTS:
1. TARGET SCOPE & SAFETY:
   - Only propose commands for authorized targets. Never generate malicious exploits, DDoS payloads, brute-force dictionaries, or unauthorized intrusion scripts.
   - Every suggested command MUST map to an approved tool and operation identifier from the Aegis Supported Operations Registry:
     * nmap_quick: Quick TCP scan (top 100 ports, -sT -F)
     * nmap_common_tcp: Common TCP ports (ports 1-1000, -sT -p 1-1000)
     * nmap_all_tcp: All TCP ports (ports 1-65535, -sT -p-)
     * nmap_service_detection: Service version detection (-sT -sV -F)
     * nmap_full_tcp_detailed: Full TCP detailed scan (-sT -A -T4 -p-)
     * http_service_check: Bounded web service diagnostic (HTTP/HTTPS HEAD/GET)
     * dns_reverse_lookup: Host resolution and PTR diagnostic
   - If user asks for an unsupported or dangerous tool (e.g. hydra, metasploit, sqlmap), politely explain that Aegis restricts execution to approved diagnostic auditing operations and explain how defensive assessments should proceed instead.

3. REMEDIATION & PRIVILEGE RESTRICTION:
   - Aegis is strictly an exposure diagnostic platform. It NEVER executes remediation commands, host firewall configuration, or privileged system commands (e.g. sudo, ufw, iptables, systemctl).
   - If the user asks to execute an administrative or firewall command (such as 'sudo ufw allow 80/tcp'), explain what the command does, state that Aegis does not execute privileged system commands for safety, advise the administrator to run it directly in their host terminal, and set suggested_command to null.

2. STRUCTURED RESPONSE:
   You must respond in valid JSON matching this schema:
   {
     "reply": "Your friendly, expert explanation in simple, clear English.",
     "suggested_command": {
       "tool": "nmap",
       "operation_id": "nmap_full_tcp_detailed",
       "command_display": "nmap -A -T4 -p- 127.0.0.1",
       "purpose": "Comprehensive scan of all 65,535 TCP ports with OS detection, service banners, and default NSE scripts.",
       "arguments_explanation": {
         "-A": "Enables OS detection, service version detection, script scanning, and traceroute.",
         "-T4": "Aggressive timing template for faster execution on reliable networks.",
         "-p-": "Audits all TCP ports from 1 through 65535."
       },
       "expected_output": "Full port list with software daemon versions, operating system fingerprints, and traceroute hops.",
       "performance_considerations": "Scanning 65,535 ports with active version detection takes 3-10+ minutes depending on network latency.",
       "operational_impact": "High packet rate; may trigger security monitoring or host rate limiters.",
       "prerequisites": "Target must be an authorized test system.",
       "safety_warnings": "Run only in authorized lab or staging environments. Service detection sends active protocol probes.",
       "is_supported": true,
       "target": "127.0.0.1",
       "plan": {
         "operation_id": "nmap_full_tcp_detailed",
         "target": "127.0.0.1"
       }
     } // Set to null if user is just asking a question and no command is needed
   }
"""


def build_offline_copilot_response(
    user_input: str,
    active_scan: Optional[Dict[str, Any]],
    has_history: bool = False
) -> Dict[str, Any]:
    """
    Intelligent heuristic fallback when OpenAI API key is missing or network fails.
    Matches user intent to approved registry operations and generates complete command cards.
    """
    clean = (user_input or "").lower().strip()
    target = "127.0.0.1"
    if active_scan and active_scan.get("target"):
        target = active_scan["target"]

    # If the user message explicitly specifies an IP address, use it
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", clean)
    if ip_match:
        target = ip_match.group(0)

    # Match intent
    suggested_op = None
    reply_text = ""

    # Check if user is asking what Aegis does or about the platform
    is_about_aegis = any(k in clean for k in (
        "what aegis does", "what does aegis", "explain what aegis", "about aegis",
        "what is aegis", "how aegis works", "aegis port scanner does", "aegis scanner does",
        "aegis do", "overview of aegis", "explain aegis", "aegis port scanner"
    ))
    do_not_scan = any(k in clean for k in (
        "do not run a scan", "don't run a scan", "dont run a scan",
        "do not scan", "don't scan", "dont scan", "no scan",
        "without scanning", "without running a scan"
    ))

    # Check for firewall and privileged administrative / remediation commands
    is_firewall_cmd = bool(re.search(r"\b(ufw|iptables|firewalld|firewall-cmd|netsh)\b", clean))
    is_admin_cmd = (
        bool(re.search(r"\bsudo\b", clean)) or
        bool(re.search(r"\bsystemctl\b", clean)) or
        bool(re.search(r"\bservice\s+[a-zA-Z0-9_-]+\s+(start|stop|restart|status)", clean)) or
        bool(re.search(r"\b(chmod|chown|apt|apt-get|yum|dnf)\b", clean))
    )

    if is_about_aegis:
        suggested_op = None
        reply_text = (
            "Aegis Port Scanner is a Flask-based network security assessment dashboard designed to audit "
            "authorized hosts using Nmap (via python-nmap) to identify open TCP ports and listening services.\\n\\n"
            "Key confirmed features of Aegis include:\\n"
            "• Deterministic Risk Analyzer: Inspects discovered ports against verified vulnerability rules to classify risk "
            "(LOW, MEDIUM, HIGH, CRITICAL) and computes an objective 0–100 Security Score with itemized exposure deductions.\\n"
            "• Service Fingerprints & Knowledge Base: Maps open ports to curated cybersecurity knowledge cards containing "
            "typical software uses, security implications, and defensive remediation guidance.\\n"
            "• Storage & Visual Analytics: Persistently records all scan results and command audit history in an SQLite "
            "database, visualized through interactive risk charts, metrics, and scan comparisons.\\n"
            "• Multi-Format Reporting: Exports professional assessment documentation in TXT, PDF (via ReportLab), CSV, and JSON formats.\\n\\n"
            "As requested, no scan was executed, scheduled, or initiated."
        )

    elif is_firewall_cmd or is_admin_cmd:
        suggested_op = None
        if "ufw" in clean:
            port_match = re.search(r"(\d+)(?:/(tcp|udp))?", clean)
            port_spec = port_match.group(0) if port_match else "specified port"
            reply_text = (
                f"The command you provided (`{user_input.strip()}`) is a host firewall configuration command "
                f"for Uncomplicated Firewall (UFW) to permit traffic on {port_spec}.\n\n"
                "• Security Policy: Aegis is a diagnostic exposure assessment platform and does NOT execute "
                "host configuration, administrative changes, or privileged commands (`sudo`/`ufw`). "
                "Arbitrary system modification is restricted to protect server integrity and prevent privilege escalation.\n\n"
                "• Recommended Action: To apply this rule, an authorized system administrator must run it "
                f"directly in the host's terminal console:\n"
                f"    sudo ufw allow {port_spec}\n"
                "    sudo ufw status verbose\n\n"
                f"After applying the rule, you can use Aegis to run a Quick Scan (`-sT -F`) or Service Detection (`-sV`) against '{target}' "
                "to verify whether the port is open and accessible across the network."
            )
        elif "iptables" in clean:
            reply_text = (
                f"The command you provided (`{user_input.strip()}`) is an iptables packet filtering rule.\n\n"
                "• Security Policy: Aegis does not execute host firewall modifications or privileged system commands (`sudo`).\n\n"
                "• Recommended Action: Apply iptables rules directly on the host console using administrator privileges. "
                f"You can subsequently use Aegis to audit '{target}' and confirm network accessibility."
            )
        else:
            reply_text = (
                f"The command you requested (`{user_input.strip()}`) is a privileged administrative command.\n\n"
                "• Security Policy: Aegis strictly performs non-destructive network exposure diagnostics and does not "
                "execute host administrative tools, package managers, or privileged commands (`sudo`).\n\n"
                "• Recommended Action: Execute administrative tasks directly in your host terminal. "
                f"Aegis can assist by performing non-intrusive scans against '{target}' to audit open ports and services."
            )

    elif any(k in clean for k in ("all tcp", "full tcp", "all port", "every port", "-p-", "deep scan", "aggressive", "-a")) and not do_not_scan:
        if any(k in clean for k in ("-a", "aggressive", "os", "version", "detailed")):
            suggested_op = "nmap_full_tcp_detailed"
            reply_text = (
                f"To comprehensively audit all 65,535 TCP ports on '{target}' along with OS fingerprinting and "
                "service versions, I recommend running the Full TCP Detailed Scan (`-A -T4 -p-`). "
                "This will sweep every port and interrogate discovered listeners with version probes."
            )
        else:
            suggested_op = "nmap_all_tcp"
            reply_text = (
                f"To check all 65,535 TCP listening ports on '{target}' without the overhead of deep script probing, "
                "I recommend the All TCP Ports Scan (`-sT -p-`)."
            )

    elif any(k in clean for k in ("service version", "version", "-sv", "banner", "software")):
        suggested_op = "nmap_service_detection"
        reply_text = (
            f"To identify exact application names and version banners on '{target}', "
            "I recommend the Service Version Detection scan (`-sT -sV -F`). "
            "This sends protocol-specific probes to open ports to extract banner information."
        )

    elif any(k in clean for k in ("web", "http", "https", "website", "title", "header", "url")):
        suggested_op = "http_service_check"
        reply_text = (
            f"To safely verify whether web services are actively listening on '{target}', "
            "I suggest running the Bounded Web Service Diagnostic. This will probe standard HTTP/HTTPS ports "
            "to check status codes, Server headers, and HTML titles without intrusive fuzzing."
        )

    elif any(k in clean for k in ("dns", "ptr", "reverse", "resolve", "hostname")):
        suggested_op = "dns_reverse_lookup"
        reply_text = (
            f"To inspect DNS records and reverse PTR hostnames for '{target}', "
            "I suggest the Host Resolution & Reverse DNS diagnostic."
        )

    elif any(k in clean for k in ("common", "standard port", "1-1000", "top 1000")):
        suggested_op = "nmap_common_tcp"
        reply_text = (
            f"To survey well-known privileged and registered services (ports 1–1000) on '{target}', "
            "I recommend the Common TCP Ports Scan (`-sT -p 1-1000`)."
        )

    elif any(k in clean for k in ("quick", "fast", "top 100", "rapid")):
        suggested_op = "nmap_quick"
        reply_text = (
            f"To perform a rapid scan of the 100 most frequently exposed TCP ports on '{target}', "
            "I recommend the standard Quick Scan (`-sT -F`)."
        )

    elif any(k in clean for k in ("explain risk", "risk", "port 21", "port 22", "port 80", "port 445", "score", "why is")):
        reply_text = (
            f"Aegis uses transparent deterministic risk rules to evaluate exposure on '{target}'. "
            "High-risk services (such as unencrypted FTP on port 21 or direct SMB on port 445) create perimeter exposure "
            "because they allow network sniffing or lateral exploitation. Each finding applies mathematical deductions "
            "to your deterministic Security Score. You can inspect the Service Fingerprint cards and Remediation Playbook "
            "for exact mitigation steps. For further analysis, running a service version detection scan is the recommended next step."
        )

    elif any(k in clean for k in ("next command", "suggest", "recommend", "what next", "follow up")):
        # Context-aware recommendation based on active scan findings
        ports = active_scan.get("ports", []) if active_scan else []
        has_http = any(p.get("port") in (80, 443, 8080, 8443) or "http" in str(p.get("service", "")).lower() for p in ports)

        if has_http:
            suggested_op = "http_service_check"
            reply_text = (
                f"Based on your previous scan findings showing web listener(s) on '{target}', "
                "I recommend a Bounded Web Service Diagnostic to inspect HTTP response codes, Server banners, and page titles."
            )
        elif ports:
            suggested_op = "nmap_service_detection"
            reply_text = (
                f"Your previous scan discovered {len(ports)} open TCP port(s). The logical next step is "
                "Service Version Detection (`-sT -sV -F`) to determine which application versions are running on those listeners."
            )
        else:
            suggested_op = "nmap_all_tcp"
            reply_text = (
                f"No open ports were recorded in the top 100 on '{target}'. To rule out services listening on non-standard ports, "
                "the recommended next step is an All TCP Ports Scan (`-sT -p-`)."
            )

    else:
        if has_history:
            reply_text = (
                f"I reviewed your request regarding '{target}'. I couldn't match this directly to an approved "
                "diagnostic operation. Aegis Copilot supports authorized Nmap auditing (Quick, All Ports, Service Detection), "
                "web service diagnostics, and port risk analysis. "
                "Please specify what diagnostic operation or security explanation you would like to run."
            )
        else:
            reply_text = (
                f"Hello! I am your Aegis AI Security Copilot. I can assist you with auditing '{target}'. "
                "You can ask me to scan all ports, detect service versions, check web services, or explain specific findings. "
                "Would you like to run an in-depth service detection scan or audit web endpoints?"
            )

    if do_not_scan:
        suggested_op = None

    cmd_card = None
    if suggested_op and suggested_op in COMMAND_REGISTRY:
        op_def = COMMAND_REGISTRY[suggested_op]
        cmd_card = {
            "tool": op_def["tool"],
            "operation": op_def["operation_id"],
            "operation_id": op_def["operation_id"],
            "command_string": op_def["command_template"].format(target=target),
            "command_display": op_def["command_template"].format(target=target),
            "purpose": op_def["purpose"],
            "arguments_breakdown": op_def["arguments_explanation"],
            "arguments_explanation": op_def["arguments_explanation"],
            "expected_output": op_def["expected_output"],
            "performance_considerations": op_def["performance_considerations"],
            "operational_impact": op_def["operational_impact"],
            "prerequisites": op_def["prerequisites"],
            "safety_warning": op_def["safety_warnings"],
            "safety_warnings": op_def["safety_warnings"],
            "is_supported": op_def["is_supported"],
            "target": target,
            "plan": {
                "operation_id": op_def["operation_id"],
                "target": target
            }
        }

    return {
        "reply": reply_text,
        "suggested_command": cmd_card,
        "command_card": cmd_card,
        "model": "offline-expert-heuristic"
    }


def generate_copilot_response(
    messages_history: List[Dict[str, str]],
    user_message: str,
    active_scan_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Main entry point for generating a Copilot response to a user query.
    Attempts live LLM completion first; falls back gracefully to offline expert heuristics.
    """
    api_key = os.environ.get("GEMINI_API_KEY", "").strip() or os.environ.get("OPENAI_API_KEY", "").strip()

    target = "127.0.0.1"
    if active_scan_data and active_scan_data.get("target"):
        target = active_scan_data["target"]

    has_history = bool(messages_history and len(messages_history) > 0)

    # If no API key configured, use offline heuristic
    if not api_key:
        return build_offline_copilot_response(user_message, active_scan_data, has_history=has_history)

    # Build prompt context with scan state
    context_lines = [f"Target Scope: {target}"]
    if active_scan_data:
        context_lines.append(f"Overall Risk: {active_scan_data.get('overall_risk', 'LOW')}")
        ports = active_scan_data.get("ports", [])
        if ports:
            p_strs = [f"{p.get('port')}/{p.get('protocol', 'tcp')} ({p.get('service', 'unknown')}, {p.get('risk', 'LOW')})" for p in ports]
            context_lines.append(f"Known Open Ports: {', '.join(p_strs)}")
        else:
            context_lines.append("Known Open Ports: None (0 ports detected).")

    system_with_context = COPILOT_SYSTEM_PROMPT + "\n\nACTIVE ASSESSMENT CONTEXT:\n" + "\n".join(context_lines)

    formatted_messages = [{"role": "system", "content": system_with_context}]

    # Include recent conversation turns (up to last 6)
    for m in (messages_history or [])[-6:]:
        r = m.get("role", "user")
        c = m.get("content", "")
        if r in ("user", "assistant") and c:
            formatted_messages.append({"role": r, "content": c})

    formatted_messages.append({"role": "user", "content": user_message})

    try:
        raw_res, model_used = call_chat_messages(
            messages=formatted_messages,
            timeout=25,
            json_mode=True
        )
        if isinstance(raw_res, dict) and "reply" in raw_res:
            raw_res["model"] = model_used
            # Ensure target is stamped on command card if present
            if raw_res.get("suggested_command"):
                cmd = raw_res["suggested_command"]
                cmd["target"] = target
                if "plan" in cmd and isinstance(cmd["plan"], dict):
                    cmd["plan"]["target"] = target
            return raw_res
    except (AIProviderError, Exception) as e:
        logger.warning("Live AI Copilot call failed (%s); switching to offline heuristic.", e)

    fallback = build_offline_copilot_response(user_message, active_scan_data, has_history=has_history)
    fallback["_notice"] = "Live AI provider unavailable; expert heuristic response provided."
    return fallback


def analyze_command_findings(
    operation_id: str,
    target: str,
    structured_findings: List[Dict[str, Any]],
    web_observations: List[Dict[str, Any]],
    raw_output: str
) -> Dict[str, Any]:
    """
    Automatically analyzes the actual structured output of a completed command execution
    and produces an accessible, actionable security explanation.
    """
    total_ports = len(structured_findings)
    open_port_nums = [f"{f['port']}/{f.get('protocol', 'tcp')} ({f.get('service', 'unknown')})" for f in structured_findings]

    observations = []
    recommendations = []
    next_steps = []

    # 1. Open Port Observations
    if total_ports == 0:
        summary = f"No open TCP ports or active listeners were observed on {target} during operation '{operation_id}'."
        observations.append({
            "title": "Clean Perimeter Filter",
            "evidence": "0 open sockets detected",
            "explanation": "No listening services responded to probe packets. Host is either inactive, dropping unsolicited packets, or filtering all tested ports.",
            "confidence": "High",
            "recommended_action": "Maintain defensive firewall configuration."
        })
    else:
        summary = f"Detected {total_ports} open TCP port(s) on target {target}: {', '.join(open_port_nums[:5])}."
        for f in structured_findings[:6]:
            observations.append({
                "title": f"Active Listener: Port {f['port']} ({f.get('service', 'unknown')})",
                "evidence": f"Socket state 'open', Risk rating {f.get('risk', 'LOW')}",
                "explanation": f["reason"],
                "confidence": "High (Confirmed TCP Socket)",
                "recommended_action": f"Review necessity of port {f['port']}. Restrict access via firewall."
            })

    # 2. Web Service Observations
    if web_observations:
        for ws in web_observations:
            observations.append({
                "title": f"Web Service Confirmed on Port {ws['port']} ({ws.get('scheme', 'http').upper()})",
                "evidence": f"HTTP status {ws.get('status_code')} · Server: '{ws.get('server_header', 'Undisclosed')}'",
                "explanation": f"Web server responded with HTML title: '{ws.get('html_title', 'None')}'. This confirms an active web application.",
                "confidence": "High (HTTP Handshake Complete)",
                "recommended_action": "Ensure HTTPS is enforced with valid TLS certificates and security headers."
            })

    # 3. Contextual Follow-up Suggestions
    has_web = any(f.get("port") in (80, 443, 8080, 8443) or "http" in str(f.get("service", "")).lower() for f in structured_findings)
    if has_web and operation_id != "http_service_check":
        next_steps.append("Run 'Bounded Web Service Diagnostic' to inspect HTTP status codes, headers, and certificates.")

    if operation_id == "nmap_quick" and total_ports > 0:
        next_steps.append("Run 'Service Version Detection' to identify the specific software versions on the detected ports.")

    if total_ports > 0 and operation_id not in ("nmap_all_tcp", "nmap_full_tcp_detailed"):
        next_steps.append("Consider scanning all 65,535 ports to ensure no backdoors or secondary administrative services are hidden on high ports.")

    recommendations.append("Apply the principle of least privilege to listening services.")
    recommendations.append("Enforce host-based firewall rules to restrict management ports to authorized IP addresses.")

    return {
        "summary": summary,
        "observations": observations,
        "recommendations": recommendations,
        "next_steps": next_steps,
        "operation_id": operation_id,
        "target": target,
        "analyzed_at": datetime.now().strftime("%d %B %Y, %H:%M")
    }
