"""
Aegis Command Output Parser
===========================
Parses raw terminal output and structured responses from approved Aegis tools
into normalized, deterministic findings.

Extracts:
  - Discovered TCP/UDP ports and states
  - Service names, application versions, and product banners
  - OS detection and default NSE script findings
  - HTTP/HTTPS status, titles, and headers
  - DNS resolution records

Never modifies deterministic risk ratings or invents findings.
"""

import re
import defusedxml.ElementTree as ET
from typing import Any, Dict, List, Optional
from risk_analyzer import analyze_port
from service_fingerprints import get_service_fingerprint


def parse_nmap_text_output(raw_text: str, target: str) -> List[Dict[str, Any]]:
    """
    Parses standard Nmap text output into a list of structured findings.
    Matches lines like: '22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)'
    """
    findings = []
    if not raw_text:
        return findings

    # Regex matching port lines: PORT STATE SERVICE [VERSION/EXTRAINFO...]
    # Example: "80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))"
    port_pattern = re.compile(
        r"^(\d+)/(tcp|udp)\s+(\w+)\s+([^\s]+)(?:\s+(.*))?$",
        re.MULTILINE
    )

    for match in port_pattern.finditer(raw_text):
        port_num = int(match.group(1))
        protocol = match.group(2).lower()
        state = match.group(3).lower()
        service_name = match.group(4)
        version_info = (match.group(5) or "").strip()

        # Only process open ports as exposure findings
        if state != "open":
            continue

        # Deterministic risk rating using existing Aegis risk analyzer
        analyzed = analyze_port(port_num, service_name)
        risk = analyzed.get("risk", "LOW")
        base_reason = analyzed.get("reason", "Open network port detected.")

        if version_info:
            full_reason = f"{base_reason} Observed banner: {version_info}."
        else:
            full_reason = base_reason

        # Attach educational fingerprint card
        fp = get_service_fingerprint(
            port_num,
            service=service_name,
            profile_id="comprehensive",
            deterministic_risk=risk
        )

        findings.append({
            "port": port_num,
            "protocol": protocol,
            "state": state,
            "service": service_name,
            "version": version_info if version_info else None,
            "risk": risk,
            "reason": full_reason,
            "remediation": analyzed.get("remediation", {}),
            "fingerprint": fp,
            "source": "nmap"
        })

    return findings


def parse_nmap_xml_output(xml_text: str, target: str) -> List[Dict[str, Any]]:
    """
    Parses Nmap XML output (-oX -) when available for deep service and script analysis.
    """
    findings = []
    if not xml_text:
        return findings

    try:
        root = ET.fromstring(xml_text)
        for host in root.findall("host"):
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                port_id = int(port_elem.attrib.get("portid", 0))
                proto = port_elem.attrib.get("protocol", "tcp")
                
                state_elem = port_elem.find("state")
                state = state_elem.attrib.get("state", "unknown") if state_elem is not None else "unknown"
                if state != "open":
                    continue

                service_elem = port_elem.find("service")
                srv_name = service_elem.attrib.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.attrib.get("product", "") if service_elem is not None else ""
                version = service_elem.attrib.get("version", "") if service_elem is not None else ""
                extrainfo = service_elem.attrib.get("extrainfo", "") if service_elem is not None else ""

                version_parts = [p for p in (product, version, extrainfo) if p]
                version_str = " ".join(version_parts) if version_parts else None

                # Extract script outputs if present
                scripts = []
                for s in port_elem.findall("script"):
                    s_id = s.attrib.get("id", "")
                    s_out = s.attrib.get("output", "")
                    if s_id and s_out:
                        scripts.append({"id": s_id, "output": s_out[:200]})

                analyzed = analyze_port(port_id, srv_name)
                risk = analyzed.get("risk", "LOW")
                reason = analyzed.get("reason", "Open socket detected.")
                if version_str:
                    reason = f"{reason} Detected banner: {version_str}."

                findings.append({
                    "port": port_id,
                    "protocol": proto,
                    "state": state,
                    "service": srv_name,
                    "version": version_str,
                    "scripts": scripts if scripts else None,
                    "risk": risk,
                    "reason": reason,
                    "remediation": analyzed.get("remediation", {}),
                    "fingerprint": get_service_fingerprint(port_id, srv_name, profile_id="comprehensive", deterministic_risk=risk),
                    "source": "nmap_xml"
                })

    except ET.ParseError:
        logger.debug("Failed to parse Nmap XML; falling back to text parsing.")

    return findings


def parse_execution_output(
    operation_id: str,
    target: str,
    raw_output: str,
    tool_metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Master parser routing command outputs to specific format parsers.

    Returns:
        Dictionary with:
          - findings: List[Dict[str, Any]]
          - web_observations: List[Dict[str, Any]]
          - summary: str
          - total_open_ports: int
          - os_detection: Optional[str]
    """
    raw_text = raw_output or ""
    findings = []
    web_observations = []
    os_detection = None

    if operation_id.startswith("nmap_"):
        # Check if XML is present in raw_output
        if "<?xml" in raw_text and "<nmaprun" in raw_text:
            xml_part = raw_text[raw_text.find("<?xml"):]
            findings = parse_nmap_xml_output(xml_part, target)

        if not findings:
            findings = parse_nmap_text_output(raw_text, target)

        # Look for OS detection strings in Nmap output
        os_match = re.search(r"OS details:\s*([^\r\n]+)", raw_text, re.IGNORECASE)
        if os_match:
            os_detection = os_match.group(1).strip()
        else:
            agg_os = re.search(r"Service Info:\s*OS:\s*([^\r\n;]+)", raw_text, re.IGNORECASE)
            if agg_os:
                os_detection = agg_os.group(1).strip()

        open_count = len(findings)
        summary = f"Nmap execution completed on target '{target}'. {open_count} open TCP port(s) detected and analyzed."

    elif operation_id == "http_service_check":
        # Tool metadata contains results from web_prober
        meta = tool_metadata or {}
        web_services = meta.get("web_services", [])
        web_observations = web_services

        for ws in web_services:
            p_num = ws["port"]
            srv = "https" if ws.get("scheme") == "https" else "http"
            analyzed = analyze_port(p_num, srv)
            findings.append({
                "port": p_num,
                "protocol": "tcp",
                "state": "open",
                "service": srv,
                "version": ws.get("server_header"),
                "html_title": ws.get("html_title"),
                "status_code": ws.get("status_code"),
                "risk": analyzed.get("risk", "LOW"),
                "reason": (
                    f"HTTP service confirmed responding with status {ws.get('status_code')} "
                    f"({ws.get('status_message', 'OK')}). Server header: '{ws.get('server_header', 'Undisclosed')}'."
                ),
                "remediation": analyzed.get("remediation", {}),
                "fingerprint": get_service_fingerprint(p_num, srv, profile_id="service_detection", deterministic_risk=analyzed.get("risk", "LOW")),
                "source": "web_prober"
            })

        summary = (
            f"Web service diagnostic completed on target '{target}'. "
            f"{len(web_services)} active HTTP/HTTPS endpoint(s) verified."
        )

    elif operation_id == "dns_reverse_lookup":
        meta = tool_metadata or {}
        summary = (
            f"DNS resolution completed for '{target}'. "
            f"Resolved IP addresses: {', '.join(meta.get('ip_addresses', [])) or 'None'}. "
            f"Reverse PTR: '{meta.get('ptr_record') or 'No PTR record found'}'."
        )

    else:
        summary = f"Operation '{operation_id}' completed for target '{target}'."

    return {
        "operation_id": operation_id,
        "target": target,
        "findings": findings,
        "web_observations": web_observations,
        "os_detection": os_detection,
        "total_open_ports": len(findings),
        "summary": summary
    }
