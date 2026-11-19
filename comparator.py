"""Aegis Exposure Comparison Engine.

Compares two historical port scans for the same normalized target and computes
an exposure diff (newly detected ports, ports not detected in later scan,
unchanged ports, and changed service details).
"""

import logging
from database import get_scan_details
from scanner import SCAN_PROFILES

logger = logging.getLogger(__name__)


class ComparisonError(Exception):
    """User-displayable comparison error."""


class ScanNotFoundError(ComparisonError):
    """Raised when one or both scan IDs cannot be found."""


class TargetMismatchError(ComparisonError):
    """Raised when comparing scans for different targets."""


# Actionable exposure remediation hints for newly discovered ports
PORT_REMEDIATION_HINTS = {
    21: "Disable FTP and migrate to SFTP (port 22) or FTPS to prevent cleartext credential transmission.",
    22: "Restrict SSH to trusted IP addresses, enforce key-based authentication, and enable Fail2ban.",
    23: "Disable Telnet immediately; unencrypted sessions expose admin credentials. Migrate to SSH.",
    80: "Enforce HTTPS redirect to port 443 with TLS certificates and enable HSTS headers.",
    135: "Block MSRPC port 135 at the network perimeter; restrict Windows RPC to internal subnets only.",
    443: "Maintain current TLS certificate validity and disable legacy cipher suites (TLS 1.0/1.1).",
    445: "Block SMB port 445 at perimeter firewalls to prevent remote code execution and lateral movement.",
    3306: "Bind MySQL to localhost (127.0.0.1) or restrict access to designated application servers via firewall.",
    3389: "Place RDP behind a VPN gateway, enforce Network Level Authentication (NLA), and enable lockout policies.",
}


def get_port_remediation_hint(port: int, service: str) -> str:
    """Returns tailored remediation guidance for a newly detected port."""
    if port in PORT_REMEDIATION_HINTS:
        return PORT_REMEDIATION_HINTS[port]
    srv_lower = str(service).lower()
    for p, hint in PORT_REMEDIATION_HINTS.items():
        if srv_lower in hint.lower():
            return hint
    return (
        f"Verify whether service '{service}' (port {port}) is required to be exposed. "
        "If not required publicly, block or restrict it using host-level or perimeter firewall rules."
    )


def compare_scans(scan_a_id: int, scan_b_id: int) -> dict:
    """Compares two historical scans and generates a structured exposure diff.

    Args:
        scan_a_id: ID of the first scan (typically earlier/baseline).
        scan_b_id: ID of the second scan (typically later/current).

    Returns:
        Structured dictionary containing scan metadata, categorized findings,
        summary statistics, and detection caveats.

    Raises:
        ScanNotFoundError: If either scan ID does not exist.
        TargetMismatchError: If the two scans target different hosts.
        ComparisonError: If scan IDs are identical or invalid.
    """
    try:
        id_a = int(scan_a_id)
        id_b = int(scan_b_id)
    except (TypeError, ValueError):
        raise ComparisonError("Scan IDs must be valid integers.")

    if id_a == id_b:
        raise ComparisonError("Cannot compare a scan against itself. Please select two distinct scans.")

    scan_a = get_scan_details(id_a)
    if scan_a is None:
        raise ScanNotFoundError(f"Base scan #{id_a} was not found.")

    scan_b = get_scan_details(id_b)
    if scan_b is None:
        raise ScanNotFoundError(f"Compared scan #{id_b} was not found.")

    # Target normalization and validation
    target_a = str(scan_a.get("target", "")).strip().lower()
    target_b = str(scan_b.get("target", "")).strip().lower()

    if target_a != target_b:
        raise TargetMismatchError(
            f"Target mismatch: Scan comparisons are only permitted between scans of the same target "
            f"('{scan_a.get('target')}' vs '{scan_b.get('target')}')."
        )

    # Order determination: earlier scan is the baseline; later scan is the compared scan
    if scan_a["id"] < scan_b["id"]:
        earlier_scan = scan_a
        later_scan = scan_b
    else:
        earlier_scan = scan_b
        later_scan = scan_a

    # Extract port dictionaries
    ports_earlier = {int(p["port"]): p for p in earlier_scan.get("ports", [])}
    ports_later = {int(p["port"]): p for p in later_scan.get("ports", [])}

    # 1. Newly detected open ports (in later, but not in earlier)
    newly_detected = []
    for port, p in sorted(ports_later.items()):
        if port not in ports_earlier:
            raw_srv = p.get("service")
            srv = (raw_srv.strip() if isinstance(raw_srv, str) and raw_srv.strip() else "unknown")
            raw_state = p.get("state")
            state = (raw_state.strip() if isinstance(raw_state, str) and raw_state.strip() else "open")
            risk = str(p.get("risk") or "LOW").upper()
            raw_reason = p.get("reason")
            reason = (raw_reason.strip() if isinstance(raw_reason, str) and raw_reason.strip() else "Open port detected.")
            newly_detected.append({
                "port": port,
                "protocol": p.get("protocol") or "tcp",
                "state": state,
                "service": srv,
                "risk": risk,
                "reason": reason,
                "exposure_impact": (
                    f"Newly detected service '{srv}' on port {port} ({risk} risk) "
                    f"expands the attack surface of {later_scan.get('target')}."
                ),
                "remediation": get_port_remediation_hint(port, srv),
            })

    # 2. Ports detected previously but NOT detected in later scan
    # CAUTION: We do not claim the port is definitively closed or disabled.
    not_detected_in_later = []
    for port, p in sorted(ports_earlier.items()):
        if port not in ports_later:
            raw_srv = p.get("service")
            srv = (raw_srv.strip() if isinstance(raw_srv, str) and raw_srv.strip() else "unknown")
            risk = str(p.get("risk") or "LOW").upper()
            raw_reason = p.get("reason")
            reason = (raw_reason.strip() if isinstance(raw_reason, str) and raw_reason.strip() else "Previously open port.")
            not_detected_in_later.append({
                "port": port,
                "protocol": p.get("protocol") or "tcp",
                "state": "not_detected",
                "service": srv,
                "risk": risk,
                "reason": reason,
                "status_note": (
                    f"Port {port} ({srv}) was detected in Scan #{earlier_scan['id']} ({risk} risk) "
                    "but was not detected in Scan #{later_scan['id']}. "
                    "Note: This does not confirm the service was disabled or port closed; "
                    "detection depends on scan profile scope, firewall filtering, host state, or network conditions."
                ),
            })

    # 3. Unchanged ports & 4. Changed service information
    unchanged = []
    changed_service = []

    for port, p_later in sorted(ports_later.items()):
        if port in ports_earlier:
            p_earlier = ports_earlier[port]
            raw_e_srv = p_earlier.get("service")
            earlier_srv = (raw_e_srv.strip() if isinstance(raw_e_srv, str) and raw_e_srv.strip() else "unknown")
            raw_l_srv = p_later.get("service")
            later_srv = (raw_l_srv.strip() if isinstance(raw_l_srv, str) and raw_l_srv.strip() else "unknown")
            raw_e_state = p_earlier.get("state")
            earlier_state = (raw_e_state.strip() if isinstance(raw_e_state, str) and raw_e_state.strip() else "open")
            raw_l_state = p_later.get("state")
            later_state = (raw_l_state.strip() if isinstance(raw_l_state, str) and raw_l_state.strip() else "open")
            later_risk = str(p_later.get("risk") or "LOW").upper()

            if earlier_srv.lower() == later_srv.lower() and earlier_state.lower() == later_state.lower():
                unchanged.append({
                    "port": port,
                    "protocol": p_later.get("protocol") or "tcp",
                    "state": later_state,
                    "service": later_srv,
                    "risk": later_risk,
                    "reason": p_later.get("reason") or "Consistent open port finding.",
                })
            else:
                changed_service.append({
                    "port": port,
                    "protocol": p_later.get("protocol") or "tcp",
                    "earlier_service": earlier_srv,
                    "later_service": later_srv,
                    "earlier_state": earlier_state,
                    "later_state": later_state,
                    "risk": later_risk,
                    "reason": p_later.get("reason") or "Service or state changed between audits.",
                    "change_summary": (
                        f"Service identified as '{earlier_srv}' in Scan #{earlier_scan['id']}, "
                        f"reported as '{later_srv}' in Scan #{later_scan['id']}."
                    ),
                })

    # Scan profile metadata & discrepancy notice
    profile_earlier_id = earlier_scan.get("profile_id", "quick")
    profile_later_id = later_scan.get("profile_id", "quick")
    profile_earlier = SCAN_PROFILES.get(profile_earlier_id, SCAN_PROFILES["quick"])
    profile_later = SCAN_PROFILES.get(profile_later_id, SCAN_PROFILES["quick"])

    profile_discrepancy = None
    if profile_earlier_id != profile_later_id:
        profile_discrepancy = (
            f"Notice: Scans were executed with differing scan profiles: "
            f"Scan #{earlier_scan['id']} used '{profile_earlier['name']}' ({profile_earlier['flags']}), while "
            f"Scan #{later_scan['id']} used '{profile_later['name']}' ({profile_later['flags']}). "
            "Differences in detected ports may result from differing port ranges or probe depths rather "
            "than changes in the host's actual exposure."
        )

    # Concise change summary text
    change_parts = []
    if newly_detected:
        change_parts.append(f"{len(newly_detected)} newly detected port(s)")
    if not_detected_in_later:
        change_parts.append(f"{len(not_detected_in_later)} port(s) not detected in later scan")
    if changed_service:
        change_parts.append(f"{len(changed_service)} port(s) with changed service info")
    if unchanged:
        change_parts.append(f"{len(unchanged)} unchanged port(s)")

    if not change_parts:
        summary_text = f"Both scans recorded zero open TCP listening ports for target '{earlier_scan.get('target')}'."
    else:
        summary_text = (
            f"Exposure diff for target '{earlier_scan.get('target')}': "
            + ", ".join(change_parts) + "."
        )

    caveats = (
        "Detection Limitations & Caveats: Network exposure comparisons reflect host and network "
        "responsiveness at the time of each scan. Differences may stem from scan profile arguments, "
        "network latency, packet drop, firewall rate-limiting, dynamic cloud security groups, or temporary service reboots."
    )

    score_earlier = earlier_scan.get("security_score")
    score_later = later_scan.get("security_score")
    score_delta = None
    score_interpretation = None
    if (
        score_earlier and score_later
        and score_earlier.get("score") is not None
        and score_later.get("score") is not None
    ):
        score_delta = score_later["score"] - score_earlier["score"]
        if score_delta > 0:
            score_interpretation = (
                f"Score increased by {score_delta:+d} points under the Aegis exposure heuristic, "
                "reflecting fewer detected exposure penalties in the later scan. "
                "This indicates reduced exposure under the configured weights, not proof that all vulnerabilities are resolved."
            )
        elif score_delta < 0:
            score_interpretation = (
                f"Score decreased by {score_delta:+d} points under the Aegis exposure heuristic, "
                "reflecting additional exposure penalties introduced in the later scan."
            )
        else:
            score_interpretation = "Score remained unchanged between the two scans under the Aegis exposure heuristic."

    return {
        "status": "success",
        "target": earlier_scan.get("target"),
        "earlier_scan": {
            "id": earlier_scan["id"],
            "scan_time": earlier_scan["scan_time"],
            "overall_risk": earlier_scan["overall_risk"],
            "open_port_count": earlier_scan["open_port_count"],
            "profile_id": profile_earlier_id,
            "profile_name": profile_earlier["name"],
            "profile_flags": profile_earlier["flags"],
            "security_score": score_earlier,
        },
        "later_scan": {
            "id": later_scan["id"],
            "scan_time": later_scan["scan_time"],
            "overall_risk": later_scan["overall_risk"],
            "open_port_count": later_scan["open_port_count"],
            "profile_id": profile_later_id,
            "profile_name": profile_later["name"],
            "profile_flags": profile_later["flags"],
            "security_score": score_later,
        },
        "summary": summary_text,
        "counts": {
            "newly_detected": len(newly_detected),
            "not_detected": len(not_detected_in_later),
            "changed_service": len(changed_service),
            "unchanged": len(unchanged),
            "total_earlier": len(ports_earlier),
            "total_later": len(ports_later),
        },
        "security_score_comparison": {
            "earlier_score": score_earlier,
            "later_score": score_later,
            "score_delta": score_delta,
            "interpretation": score_interpretation,
        },
        "newly_detected": newly_detected,
        "not_detected": not_detected_in_later,
        "changed_service": changed_service,
        "unchanged": unchanged,
        "profile_discrepancy": profile_discrepancy,
        "caveats": caveats,
    }
