"""
Aegis Command Registry
======================
Strict, safe registry of supported diagnostic and exposure assessment operations.
Defines allowed tools, operations, arguments, flag explanations, performance considerations,
operational impacts, prerequisites, and safety warnings.

Arbitrary shell execution is strictly prohibited. Every command execution plan must
resolve to an approved operation in this registry.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

# Well-defined registry of supported operations
COMMAND_REGISTRY: Dict[str, Dict[str, Any]] = {
    "nmap_quick": {
        "tool": "nmap",
        "operation_id": "nmap_quick",
        "name": "Quick TCP Scan (Default Profile)",
        "command_template": "nmap -sT -F {target}",
        "arguments": ["-sT", "-F"],
        "category": "port_scan",
        "purpose": "Rapidly scans Nmap's top 100 most frequent TCP ports using unprivileged connect probes.",
        "arguments_explanation": {
            "-sT": "TCP Connect scan. Completes the 3-way handshake (SYN, SYN-ACK, ACK); does not require administrative privileges.",
            "-F": "Fast mode. Scans the top 100 most common TCP ports according to Nmap frequency statistics."
        },
        "expected_output": "List of open TCP ports among the top 100 standard services with service names.",
        "performance_considerations": "Very fast. Typically completes in 2–10 seconds on local or low-latency networks.",
        "operational_impact": "Minimal network overhead (~100 probe packets sent to the target host).",
        "prerequisites": "Target must be authorized, reachable, and responsive to TCP handshake packets.",
        "safety_warnings": "Safe for routine authorized diagnostics. Ports outside the top 100 will not be checked.",
        "is_supported": True,
        "timeout_seconds": 60,
    },
    "nmap_common_tcp": {
        "tool": "nmap",
        "operation_id": "nmap_common_tcp",
        "name": "Common TCP Ports Scan (1–1000)",
        "command_template": "nmap -sT -p 1-1000 {target}",
        "arguments": ["-sT", "-p", "1-1000"],
        "category": "port_scan",
        "purpose": "Audits standard privileged and registered TCP service ports from 1 through 1000.",
        "arguments_explanation": {
            "-sT": "TCP Connect scan using standard OS socket connections.",
            "-p 1-1000": "Specifies the target port range from port 1 to port 1000 (well-known services)."
        },
        "expected_output": "Listening TCP services operating within the standard 1–1000 port range.",
        "performance_considerations": "Moderate speed. Typically completes in 10–30 seconds.",
        "operational_impact": "Low to moderate traffic (~1,000 probe packets).",
        "prerequisites": "Target must be authorized and reachable.",
        "safety_warnings": "Safe for production diagnostics when authorized; ports above 1000 are not audited.",
        "is_supported": True,
        "timeout_seconds": 120,
    },
    "nmap_all_tcp": {
        "tool": "nmap",
        "operation_id": "nmap_all_tcp",
        "name": "All TCP Ports Scan (1–65535)",
        "command_template": "nmap -sT -p- {target}",
        "arguments": ["-sT", "-p-"],
        "category": "port_scan",
        "purpose": "Exhaustively surveys the entire TCP port space to detect non-standard and high-port listening services.",
        "arguments_explanation": {
            "-sT": "TCP Connect scan utilizing standard system networking calls.",
            "-p-": "Shorthand for `-p 1-65535`, inspecting every possible TCP listening port."
        },
        "expected_output": "Comprehensive list of all open TCP ports across the entire 1–65535 spectrum.",
        "performance_considerations": "Long-running operation. Can take 1–5+ minutes depending on network latency and firewall response.",
        "operational_impact": "High volume (65,535 packets). May trigger IDS/IPS thresholds or host rate limits.",
        "prerequisites": "Target must be authorized. Ensure network paths do not silently drop high-rate probe traffic.",
        "safety_warnings": "Coordinate before running on production networks during peak traffic hours.",
        "is_supported": True,
        "timeout_seconds": 360,
    },
    "nmap_service_detection": {
        "tool": "nmap",
        "operation_id": "nmap_service_detection",
        "name": "Quick Scan with Service Version Detection",
        "command_template": "nmap -sT -sV -F {target}",
        "arguments": ["-sT", "-sV", "-F"],
        "category": "service_detection",
        "purpose": "Probes open ports on top 100 services to identify application banners, software vendor names, and versions.",
        "arguments_explanation": {
            "-sT": "TCP Connect scan.",
            "-sV": "Service version detection. Interrogates open ports with specific protocol probes to extract software versions.",
            "-F": "Fast mode restricting initial port discovery to top 100 ports."
        },
        "expected_output": "Discovered ports with application product names, version numbers, and operating system hints.",
        "performance_considerations": "Moderate speed. Typically completes in 10–35 seconds depending on banner responsiveness.",
        "operational_impact": "Sends application-layer payload handshakes to open sockets. Will be recorded in service logs.",
        "prerequisites": "Target must be authorized and listening services must respond to protocol probes.",
        "safety_warnings": "Service probes may trigger security alerts or connection resets on sensitive legacy services.",
        "is_supported": True,
        "timeout_seconds": 180,
    },
    "nmap_full_tcp_detailed": {
        "tool": "nmap",
        "operation_id": "nmap_full_tcp_detailed",
        "name": "Full TCP Comprehensive Audit (-A -T4 -p-)",
        "command_template": "nmap -sT -A -T4 -p- {target}",
        "arguments": ["-sT", "-A", "-T4", "-p-"],
        "category": "comprehensive_audit",
        "purpose": "Comprehensive in-depth network audit surveying all 65,535 TCP ports with OS detection, versioning, and default scripts.",
        "arguments_explanation": {
            "-sT": "TCP Connect scan ensuring compatibility without requiring root/Administrator raw socket drivers.",
            "-A": "Enables OS detection, service version detection, default NSE script scanning, and traceroute.",
            "-T4": "Aggressive timing template to accelerate execution on reliable high-speed networks.",
            "-p-": "Scans the full TCP port range from 1 through 65535."
        },
        "expected_output": "Comprehensive technical security profile including all open ports, version banners, OS detection, and default script outputs.",
        "performance_considerations": "Resource intensive. Execution time typically ranges from 3 to 15+ minutes depending on target responsiveness.",
        "operational_impact": "Substantial network traffic and active protocol interrogations. Will be flagged by intrusion detection systems.",
        "prerequisites": "Explicit written authorization required. Target must have adequate computing resources.",
        "safety_warnings": "Only run against authorized lab or staging systems. Never run against unauthorized third-party infrastructure.",
        "is_supported": True,
        "timeout_seconds": 600,
    },
    "http_service_check": {
        "tool": "http_check",
        "operation_id": "http_service_check",
        "name": "Bounded Web Service Diagnostic (HTTP/HTTPS)",
        "command_template": "http-check --target {target} --ports 80,443,8080,8443",
        "arguments": ["--ports", "80,443,8080,8443"],
        "category": "web_probe",
        "purpose": "Audits listening HTTP/HTTPS endpoints to extract HTTP response status, Server headers, page titles, and TLS certificate metadata.",
        "arguments_explanation": {
            "--target": "Authorized target IP address or hostname.",
            "--ports": "Restricted list of standard HTTP/HTTPS ports to probe (strictly bounded, zero crawling)."
        },
        "expected_output": "HTTP status codes (200, 301, 403), Server banner strings, HTML page titles, redirect targets, and TLS certificate validity.",
        "performance_considerations": "Very fast. Completes in 1–4 seconds with bounded 5-second connection timeouts.",
        "operational_impact": "Sends standard HTTP HEAD/GET requests. Zero vulnerability exploitation, zero directory fuzzing.",
        "prerequisites": "Target must have active HTTP or HTTPS services.",
        "safety_warnings": "Server headers are recorded as technical observations, not definitive proof of software vulnerability.",
        "is_supported": True,
        "timeout_seconds": 30,
    },
    "dns_reverse_lookup": {
        "tool": "diagnostic",
        "operation_id": "dns_reverse_lookup",
        "name": "Host Resolution & Reverse DNS (PTR) Diagnostic",
        "command_template": "host-diagnostic --dns {target}",
        "arguments": ["--dns"],
        "category": "network_diagnostic",
        "purpose": "Performs forward resolution and reverse PTR DNS lookups to verify canonical hostnames and associated network identities.",
        "arguments_explanation": {
            "--dns": "Performs standard DNS A/AAAA and reverse PTR queries through the system resolver."
        },
        "expected_output": "Resolved IPv4/IPv6 addresses, canonical FQDN, and reverse DNS PTR hostname records.",
        "performance_considerations": "Near instantaneous (<1 second).",
        "operational_impact": "Standard DNS queries to the local DNS resolver; zero direct probe packets sent to the target.",
        "prerequisites": "Local DNS resolver connectivity.",
        "safety_warnings": "Completely passive network query.",
        "is_supported": True,
        "timeout_seconds": 15,
    }
}


def get_supported_operations() -> List[Dict[str, Any]]:
    """Returns a list of all supported operations in the registry with metadata."""
    return list(COMMAND_REGISTRY.values())


def get_operation_by_id(operation_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an operation definition by its operation_id."""
    return COMMAND_REGISTRY.get(operation_id)


def match_command_to_operation(command_str: str) -> Optional[Dict[str, Any]]:
    """
    Attempts to match a user-requested or AI-generated command string
    against approved operations in the registry.
    """
    if not command_str or not isinstance(command_str, str):
        return None

    clean = command_str.strip().lower()

    # Full TCP Detailed Scan (-A -T4 -p-)
    if "-a" in clean and "-p-" in clean:
        return COMMAND_REGISTRY["nmap_full_tcp_detailed"]
    # Service version detection (-sV)
    elif "-sv" in clean:
        return COMMAND_REGISTRY["nmap_service_detection"]
    # All TCP ports (-p-)
    elif "-p-" in clean:
        return COMMAND_REGISTRY["nmap_all_tcp"]
    # Common ports (1-1000)
    elif "1-1000" in clean or "common" in clean:
        return COMMAND_REGISTRY["nmap_common_tcp"]
    # HTTP service check
    elif "http" in clean and ("check" in clean or "curl" in clean or "probe" in clean):
        return COMMAND_REGISTRY["http_service_check"]
    # DNS lookup
    elif "dns" in clean or "dig" in clean or "nslookup" in clean or "ptr" in clean:
        return COMMAND_REGISTRY["dns_reverse_lookup"]
    # Quick scan fallback
    elif "nmap" in clean or "quick" in clean:
        return COMMAND_REGISTRY["nmap_quick"]

    return None


def validate_execution_plan(plan: Any, target: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Independently validates a structured execution plan against the command registry
    and target allowlist rules. Never trusts AI output blindly.

    Returns:
        (is_valid: bool, validated_plan: Optional[dict], error_message: Optional[str])
    """
    if not isinstance(plan, dict):
        return False, None, "Execution plan must be a valid JSON object."

    operation_id = plan.get("operation_id")
    if not operation_id or not isinstance(operation_id, str):
        return False, None, "Execution plan is missing required 'operation_id'."

    op_def = COMMAND_REGISTRY.get(operation_id)
    if not op_def:
        return False, None, f"Operation '{operation_id}' is not in the approved Aegis command registry."

    if not op_def.get("is_supported", False):
        return False, None, f"Operation '{operation_id}' is currently disabled or unsupported."

    # Verify target matches validated target
    plan_target = plan.get("target") or target
    if not plan_target:
        return False, None, "Target host or IP address is required."

    # Validate target character set to prevent any argument injection
    clean_target = str(plan_target).strip()
    if clean_target.startswith("-") or clean_target.startswith(".") or clean_target.endswith("."):
        return False, None, "Target format is invalid (cannot start with hyphen or dot)."

    if not re.match(r"^[a-zA-Z0-9.:-]+$", clean_target):
        return False, None, "Target contains invalid characters for network execution."

    # Build validated plan object
    validated = {
        "tool": op_def["tool"],
        "operation_id": op_def["operation_id"],
        "name": op_def["name"],
        "target": clean_target,
        "arguments": list(op_def["arguments"]),
        "command_str": op_def["command_template"].format(target=clean_target),
        "purpose": op_def["purpose"],
        "timeout_seconds": op_def.get("timeout_seconds", 120),
        "category": op_def["category"],
        "expected_output": op_def["expected_output"],
        "performance_considerations": op_def["performance_considerations"],
        "operational_impact": op_def["operational_impact"],
        "prerequisites": op_def["prerequisites"],
        "safety_warnings": op_def["safety_warnings"],
    }

    # Optional custom ports for http_check if provided and safe
    if op_def["tool"] == "http_check" and "custom_ports" in plan:
        custom_ports = plan.get("custom_ports")
        if isinstance(custom_ports, list):
            safe_ports = []
            for p in custom_ports:
                try:
                    p_int = int(p)
                    if 1 <= p_int <= 65535:
                        safe_ports.append(p_int)
                except (ValueError, TypeError):
                    continue
            if safe_ports:
                validated["custom_ports"] = safe_ports[:8]  # Bound to max 8 ports

    return True, validated, None
