"""
Aegis Command Runner
====================
Secure execution engine for authorized chatbot-proposed network diagnostic operations.
Enforces:
  - Fixed executable paths & argument lists (NEVER shell=True)
  - Target scope validation
  - Process isolation, thread safety, and cancellation
  - Strict timeouts and output buffer size capping
  - Automatic output parsing and AI analysis
  - Database audit logging
"""

import json
import logging
import os
import shutil
import socket
import subprocess  # nosec B404
import threading
from datetime import datetime
from typing import Any, Dict, Optional

from command_parser import parse_execution_output
from command_registry import COMMAND_REGISTRY, validate_execution_plan
from scanner import validate_target
from web_prober import probe_web_services

logger = logging.getLogger(__name__)

# Registry for active running subprocesses to support cooperative cancellation
_ACTIVE_LOCK = threading.Lock()
ACTIVE_PROCESSES: Dict[int, subprocess.Popen] = {}
CANCELLED_EXECUTIONS = set()

# Maximum output capture size in characters (500 KB limit to prevent memory bloat)
MAX_OUTPUT_CHARS = 500_000

# Helper to find nmap executable
def find_nmap_binary() -> Optional[str]:
    """Locates the safe nmap binary on Windows or POSIX systems."""
    found = shutil.which("nmap")
    if found:
        return found
    windows_default = r"C:\Program Files (x86)\Nmap\nmap.exe"
    if os.path.isfile(windows_default):
        return windows_default
    windows_alt = r"C:\Program Files\Nmap\nmap.exe"
    if os.path.isfile(windows_alt):
        return windows_alt
    return None


def execute_dns_diagnostic(target: str) -> Dict[str, Any]:
    """Performs passive forward and reverse DNS queries safely."""
    ip_addresses = []
    ptr_record = None

    try:
        # Forward resolution
        addr_info = socket.getaddrinfo(target, None)
        for item in addr_info:
            ip = item[4][0]
            if ip not in ip_addresses:
                ip_addresses.append(ip)
    except Exception as e:
        logger.debug("DNS forward resolution failed for %s: %s", target, e)

    try:
        # Reverse PTR resolution
        resolved_ip = ip_addresses[0] if ip_addresses else target
        host_tuple = socket.gethostbyaddr(resolved_ip)
        ptr_record = host_tuple[0]
    except Exception as e:
        logger.debug("DNS reverse PTR failed for %s: %s", target, e)

    output_lines = [
        f"Host Resolution Diagnostic for '{target}'",
        "-----------------------------------------",
        f"Target query: {target}",
        f"Resolved IP(s): {', '.join(ip_addresses) if ip_addresses else 'None'}",
        f"Reverse DNS (PTR): {ptr_record if ptr_record else 'No PTR record found'}"
    ]
    return {
        "raw_output": "\n".join(output_lines),
        "metadata": {
            "ip_addresses": ip_addresses,
            "ptr_record": ptr_record
        }
    }


def run_command_in_background(
    execution_id: int,
    validated_plan: Dict[str, Any],
    db_updater_fn,
    ai_analyzer_fn
) -> None:
    """
    Background worker thread executing an approved command plan.
    Ensures safe execution, output parsing, AI analysis, and database audit updates.
    """
    operation_id = validated_plan["operation_id"]
    tool = validated_plan["tool"]
    target = validated_plan["target"]
    timeout_secs = validated_plan.get("timeout_seconds", 120)

    start_time = datetime.now().strftime("%d %B %Y, %H:%M:%S")
    db_updater_fn(execution_id, status="running", start_time=start_time)

    raw_output = ""
    exit_code = 0
    error_message = None
    tool_metadata = None

    try:
        if tool == "diagnostic" and operation_id == "dns_reverse_lookup":
            dns_res = execute_dns_diagnostic(target)
            raw_output = dns_res["raw_output"]
            tool_metadata = dns_res["metadata"]
            exit_code = 0

        elif tool == "http_check":
            custom_ports = validated_plan.get("custom_ports")
            web_res = probe_web_services(target, ports=custom_ports, timeout=4)
            tool_metadata = web_res

            lines = [
                f"Aegis Bounded Web Service Diagnostic — Target: {target}",
                f"Endpoints Probed: {web_res['total_probed']} | Confirmed Web Services: {web_res['web_services_count']}",
                "=" * 60,
                ""
            ]
            for ep in web_res["endpoints"]:
                lines.append(f"Port {ep['port']}/{ep['scheme'].upper()}:")
                if ep["http_service_detected"]:
                    lines.append(f"  Status: {ep['status_code']} ({ep['status_message'] or 'OK'})")
                    lines.append(f"  Server: {ep.get('server_header') or 'Not reported'}")
                    lines.append(f"  Title:  {ep.get('html_title') or 'No HTML title tag'}")
                    if ep.get("tls_metadata"):
                        tls = ep["tls_metadata"]
                        lines.append(f"  TLS:    {tls.get('tls_version', 'Unknown')} ({tls.get('cipher_suite', 'Unknown')})")
                else:
                    lines.append(f"  Status: No HTTP service responding ({ep.get('error') or 'Unresponsive'})")
                lines.append("")

            lines.append("Notice: Server banners and headers are unverified self-reported observations.")
            raw_output = "\n".join(lines)
            exit_code = 0

        elif tool == "nmap":
            nmap_bin = find_nmap_binary()
            if not nmap_bin:
                raise RuntimeError("Nmap binary was not found on the system. Please ensure Nmap is installed.")

            # Build command argument list safely without shell
            cmd_args = [nmap_bin] + validated_plan["arguments"] + [target]

            logger.info("Starting safe background Nmap execution [%s]: %s", execution_id, " ".join(cmd_args))

            # Launch subprocess with shell=False (MANDATORY SECURITY REQUIREMENT)
            proc = subprocess.Popen(  # nosec B603
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False
            )

            with _ACTIVE_LOCK:
                ACTIVE_PROCESSES[execution_id] = proc

            try:
                stdout_str, stderr_str = proc.communicate(timeout=timeout_secs)
                exit_code = proc.returncode
                raw_output = (stdout_str or "") + (("\n" + stderr_str) if stderr_str else "")
            except subprocess.TimeoutExpired:
                proc.kill()
                exit_code = -1
                error_message = f"Command execution timed out after {timeout_secs} seconds."
                raw_output = f"[TIMEOUT] Execution exceeded allotted limit of {timeout_secs}s and was terminated safely."
            finally:
                with _ACTIVE_LOCK:
                    ACTIVE_PROCESSES.pop(execution_id, None)

        else:
            raise ValueError(f"Unimplemented tool: {tool}")

    except Exception as e:
        logger.exception("Exception in command execution [%s]", execution_id)
        exit_code = 1
        error_message = str(e)
        raw_output = f"[ERROR] Execution failed: {str(e)}"

    # Truncate output if it exceeds size bounds
    if len(raw_output) > MAX_OUTPUT_CHARS:
        raw_output = raw_output[:MAX_OUTPUT_CHARS] + "\n... [Output truncated at 500 KB limit for memory protection]"

    # Check if cancelled cooperatively
    with _ACTIVE_LOCK:
        if execution_id in CANCELLED_EXECUTIONS:
            CANCELLED_EXECUTIONS.remove(execution_id)
            end_time = datetime.now().strftime("%d %B %Y, %H:%M:%S")
            db_updater_fn(
                execution_id,
                status="cancelled",
                raw_output=raw_output + "\n[CANCELLED] Operation cancelled by operator.",
                exit_code=130,
                end_time=end_time
            )
            return

    # Parse output into structured findings
    parsed_results = parse_execution_output(
        operation_id,
        target,
        raw_output,
        tool_metadata=tool_metadata
    )

    # Automatically generate AI Security Analyst explanation for the findings
    ai_analysis = None
    try:
        if ai_analyzer_fn:
            ai_analysis = ai_analyzer_fn(
                operation_id=operation_id,
                target=target,
                structured_findings=parsed_results["findings"],
                web_observations=parsed_results["web_observations"],
                raw_output=raw_output
            )
    except Exception as ai_err:
        logger.warning("AI analysis of command output failed: %s", ai_err)
        ai_analysis = {
            "summary": f"Execution completed for operation '{operation_id}'.",
            "findings_explanation": "AI explanation unavailable; deterministic findings recorded below.",
            "recommendations": ["Review open port table and verify service hardening."]
        }

    end_time = datetime.now().strftime("%d %B %Y, %H:%M:%S")
    final_status = "completed" if exit_code == 0 and not error_message else "failed"

    db_updater_fn(
        execution_id,
        status=final_status,
        raw_output=raw_output,
        exit_code=exit_code,
        parsed_findings=parsed_results,
        ai_analysis=ai_analysis,
        error_message=error_message,
        end_time=end_time
    )
    logger.info("Command execution [%s] finished with status '%s'.", execution_id, final_status)


def cancel_command_execution(execution_id: int) -> bool:
    """Safely terminates an active subprocess."""
    with _ACTIVE_LOCK:
        CANCELLED_EXECUTIONS.add(execution_id)
        proc = ACTIVE_PROCESSES.get(execution_id)
        if proc:
            try:
                proc.terminate()
                # Give process a moment to exit gracefully before forceful kill
                threading.Timer(2.0, lambda: proc.kill() if proc.poll() is None else None).start()
                return True
            except Exception as e:
                logger.warning("Failed to terminate process %s: %s", execution_id, e)
                return False
    return False
