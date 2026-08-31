import logging
import os
import re
import socket
import nmap

logger = logging.getLogger(__name__)

# Ensure Nmap binary is in the system PATH (Windows compatibility helper)
NMAP_DEFAULT_PATH = r"C:\Program Files (x86)\Nmap"
if NMAP_DEFAULT_PATH not in os.environ["PATH"] and os.path.exists(NMAP_DEFAULT_PATH):
    os.environ["PATH"] += os.pathsep + NMAP_DEFAULT_PATH

def validate_target(target):
    """
    Validates that the target is a valid, safe IP address or hostname.
    Returns: (is_valid, sanitized_target_or_error_msg)
    """
    if not target:
        return False, "Target cannot be empty."
        
    if not isinstance(target, str):
        return False, "Target must be a string."
        
    target = target.strip()
    
    # Restrict length
    if len(target) < 1 or len(target) > 253:
        return False, "Target length must be between 1 and 253 characters."
        
    # Restrict allowed characters to prevent command injection (only alphanumeric, dots, hyphens, colons)
    if not re.match(r"^[a-zA-Z0-9.:-]+$", target):
        return False, "Invalid characters in target. Only letters, digits, dots, hyphens, and colons are allowed."
        
    # Prevent passing option arguments (starting with hyphen)
    if target.startswith("-"):
        return False, "Target cannot start with a hyphen."
        
    # Prevent starting or ending with dots
    if target.startswith(".") or target.endswith("."):
        return False, "Target cannot start or end with a dot."
        
    # Resolve the target to verify it exists and is valid
    try:
        socket.getaddrinfo(target, None)
    except socket.gaierror:
        return False, f"Could not resolve hostname/IP: '{target}'"
        
    return True, target

def scan_target(target):
    """
    Performs a lightweight Nmap TCP port scan on the target.
    Returns: dict of results matching the expected Day 1 format.
    """
    is_valid, target_or_err = validate_target(target)
    if not is_valid:
        return {
            "target": target,
            "status": "error",
            "message": target_or_err,
            "ports": []
        }
        
    sanitized_target = target_or_err
    
    try:
        # Initialize the port scanner
        nm = nmap.PortScanner()
        
        # Run a fast, lightweight TCP connect scan (-sT) on standard ports (-F = top 100 ports)
        # We specify -sT because it does not require administrator privileges on all systems
        # and is safe and reliable.
        scan_results = nm.scan(hosts=sanitized_target, arguments="-sT -F")
        
        ports_list = []
        
        # Parse the scan results
        # Note: the key in scan_results['scan'] might be the resolved IP even if target was a hostname.
        # Therefore, we iterate over all scanned hosts in the dictionary.
        for host in scan_results.get("scan", {}):
            host_data = scan_results["scan"][host]
            
            # We look for TCP ports
            if "tcp" in host_data:
                for port, port_info in host_data["tcp"].items():
                    # The dashboard is an open-port assessment. Nmap may also
                    # report filtered or closed ports in its result structure;
                    # those are not findings to persist or risk-rate.
                    if port_info.get("state") != "open":
                        continue
                    ports_list.append({
                        "port": int(port),
                        "protocol": "tcp",
                        "state": port_info.get("state", "unknown"),
                        "service": port_info.get("name", "unknown")
                    })
                    
        # Sort ports by port number for neatness
        ports_list.sort(key=lambda x: x["port"])
        
        return {
            "target": sanitized_target,
            "status": "success",
            "ports": ports_list
        }
        
    except nmap.PortScannerError as e:
        # Log the full technical detail server-side for operator debugging.
        # SECURITY (FINDING-005): raw exception text is never sent to the client
        # because it may contain the Nmap binary path, version strings, or
        # internal command arguments.
        logger.error("Nmap scanner error for target '%s': %s", sanitized_target, e)
        return {
            "target": sanitized_target,
            "status": "error",
            "message": "Network scanning failed. Verify the target is reachable and that Nmap is installed.",
            "ports": []
        }
    except Exception:
        # logger.exception() captures the full traceback in the server log
        # without any of it reaching the API response.
        logger.exception("Unexpected error while scanning target '%s'", sanitized_target)
        return {
            "target": sanitized_target,
            "status": "error",
            "message": "An unexpected scanning error occurred.",
            "ports": []
        }
