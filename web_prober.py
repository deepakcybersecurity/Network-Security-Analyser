"""
Aegis Web Service Prober
========================
Bounded, safe HTTP/HTTPS diagnostic engine designed for authorized targets.
Extracts response status, Server header, HTML page title, and TLS metadata
without directory fuzzing, crawling, or intrusive requests.

Distinguishes between:
  1. An open TCP port
  2. A detected HTTP/HTTPS service
  3. A successful HTTP response
  4. A detected page title or server header
  5. A confirmed hostname or website identity

Treats headers and banners as observations, not definitive proof of vulnerability.
"""

import html
import logging
import re
import socket
import ssl
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

# Standard web ports to check if none specified
DEFAULT_WEB_PORTS = [80, 443, 8080, 8443]


def probe_single_endpoint(
    target: str,
    port: int,
    use_tls: bool = False,
    timeout: int = 5
) -> Dict[str, Any]:
    """
    Performs a bounded, safe HTTP or HTTPS probe against a specific target port.

    Args:
        target: Validated IP address or hostname.
        port: TCP port number (int).
        use_tls: True to probe via HTTPS; False for HTTP.
        timeout: Socket timeout in seconds (default 5).

    Returns:
        Structured observation dictionary.
    """
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{target}:{port}/"
    result: Dict[str, Any] = {
        "target": target,
        "port": port,
        "scheme": scheme,
        "url": url,
        "tcp_port_open": False,
        "http_service_detected": False,
        "successful_http_response": False,
        "status_code": None,
        "status_message": None,
        "server_header": None,
        "content_type": None,
        "html_title": None,
        "redirect_location": None,
        "tls_metadata": None,
        "error": None,
        "observation_notes": (
            "Observation Notice: Server headers and HTML titles are technical observations "
            "reported by the target endpoint. They do not constitute verified software versions "
            "or definitive proof of vulnerability."
        )
    }

    # 1. First verify TCP socket reachability before sending HTTP request
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        check = sock.connect_ex((target, port))
        sock.close()
        if check != 0:
            result["tcp_port_open"] = False
            result["error"] = f"TCP port {port} is closed or unresponsive."
            return result
        result["tcp_port_open"] = True
    except Exception as sock_err:
        result["tcp_port_open"] = False
        result["error"] = f"Socket connection failed: {str(sock_err)}"
        return result

    # 2. Extract TLS metadata if TLS is requested
    if use_tls:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # Safe non-intrusive metadata check
            with socket.create_connection((target, port), timeout=timeout) as plain_sock:
                with ctx.wrap_socket(plain_sock, server_hostname=target) as ssl_sock:
                    cert = ssl_sock.getpeercert(binary_form=False)
                    cipher = ssl_sock.cipher()
                    version = ssl_sock.version()
                    result["tls_metadata"] = {
                        "tls_version": version,
                        "cipher_suite": cipher[0] if cipher else None,
                        "subject": dict(x[0] for x in cert.get("subject", [])) if cert else None,
                        "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert else None,
                        "not_after": cert.get("notAfter") if cert else None,
                    }
        except Exception as tls_err:
            logger.debug("TLS metadata probe failed for %s:%d: %s", target, port, tls_err)
            result["tls_metadata"] = {"error": f"TLS handshake exception: {str(tls_err)}"}

    # 3. Perform bounded HTTP probe
    req = Request(
        url,
        headers={
            "User-Agent": "Aegis-Security-Scanner/2.4 (Security Assessment Probe; Authorised Lab Audit)",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Connection": "close"
        },
        method="GET"
    )

    # Disable SSL certificate verification strictly for observation purposes
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        with urlopen(req, timeout=timeout, context=ssl_context) as resp:  # nosec B310
            result["http_service_detected"] = True
            result["successful_http_response"] = (resp.status == 200)
            result["status_code"] = resp.status
            result["status_message"] = resp.reason
            result["server_header"] = resp.headers.get("Server")
            result["content_type"] = resp.headers.get("Content-Type")

            # Read bounded body (max 32 KB to avoid memory bloat)
            body_bytes = resp.read(32768)
            body_text = body_bytes.decode("utf-8", errors="replace")

            # Extract HTML <title> tag safely
            title_match = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL)
            if title_match:
                raw_title = title_match.group(1).strip()
                result["html_title"] = html.unescape(raw_title)[:120]  # Cap at 120 chars

    except HTTPError as http_err:
        # HTTP errors (e.g. 401 Unauthorized, 403 Forbidden, 404, 500) confirm an active HTTP service!
        result["http_service_detected"] = True
        result["successful_http_response"] = False
        result["status_code"] = http_err.code
        result["status_message"] = http_err.reason
        result["server_header"] = http_err.headers.get("Server")
        result["content_type"] = http_err.headers.get("Content-Type")
        result["redirect_location"] = http_err.headers.get("Location")

    except (URLError, TimeoutError, socket.timeout) as net_err:
        # Connection failed or protocol mismatch (e.g. speaking raw TCP instead of HTTP)
        result["http_service_detected"] = False
        result["error"] = f"HTTP probe unsuccessful: {str(net_err)}"

    except Exception as gen_err:
        result["http_service_detected"] = False
        result["error"] = f"Diagnostic probe exception: {str(gen_err)}"

    return result


def probe_web_services(target: str, ports: Optional[List[int]] = None, timeout: int = 4) -> Dict[str, Any]:
    """
    Audits a target host for web services across specified or default web ports.
    Distinguishes open ports from active HTTP/HTTPS servers.

    Returns:
        Structured summary with endpoint results and web service findings.
    """
    ports_to_check = ports if ports and len(ports) > 0 else DEFAULT_WEB_PORTS
    # Ensure port numbers are integers and bounded
    clean_ports = []
    for p in ports_to_check:
        try:
            p_int = int(p)
            if 1 <= p_int <= 65535 and p_int not in clean_ports:
                clean_ports.append(p_int)
        except (ValueError, TypeError):
            continue

    endpoints = []
    web_services_found = []

    for port in clean_ports[:8]:  # Limit to max 8 ports per execution
        use_tls = (port in (443, 8443))
        res = probe_single_endpoint(target, port, use_tls=use_tls, timeout=timeout)

        # If standard port 80 failed or redirected to HTTPS, or if 8080/8443, also try TLS if non-TLS failed
        if not res["http_service_detected"] and not use_tls and port in (8080, 8443):
            tls_res = probe_single_endpoint(target, port, use_tls=True, timeout=timeout)
            if tls_res["http_service_detected"]:
                res = tls_res

        endpoints.append(res)

        if res["http_service_detected"]:
            web_services_found.append({
                "port": res["port"],
                "scheme": res["scheme"],
                "url": res["url"],
                "status_code": res["status_code"],
                "status_message": res["status_message"],
                "server_header": res["server_header"] or "Undisclosed",
                "html_title": res["html_title"] or "No HTML title detected",
                "has_tls": bool(res.get("tls_metadata") and not res["tls_metadata"].get("error")),
                "evidence": f"HTTP {res.get('status_code')} on {res.get('scheme', 'http').upper()}://{target}:{res['port']}/"
            })

    return {
        "target": target,
        "total_probed": len(endpoints),
        "web_services_count": len(web_services_found),
        "web_services": web_services_found,
        "endpoints": endpoints,
        "disclaimer": (
            "Detection distinction: An open TCP port indicates an active socket listener. "
            "A web service is confirmed only when an endpoint produces a valid HTTP/HTTPS protocol response. "
            "Server banners are unverified self-reported strings."
        )
    }
