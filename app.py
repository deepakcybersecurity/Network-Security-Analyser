import sys
import os
import logging
from flask import Flask, Response, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import werkzeug.serving

# Suppress Werkzeug / Python server banner in development server (DAST-P01)
try:
    werkzeug.serving.WSGIRequestHandler.server_version = "Aegis-Scanner"
    werkzeug.serving.WSGIRequestHandler.sys_version = ""
    werkzeug.serving.WSGIRequestHandler.version_string = lambda self: "Aegis-Scanner"
except (AttributeError, TypeError):
    pass

# ---------------------------------------------------------------------------
# Bootstrap: ensure the project root is importable regardless of how the
# interpreter was launched.
# ---------------------------------------------------------------------------
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner import scan_target, validate_target
from risk_analyzer import analyze_port, calculate_overall_risk
from database import (
    clear_scan_history,
    get_dashboard_stats,
    get_scan_details,
    get_scan_history,
    init_db,
    save_scan_results,
)

# ---------------------------------------------------------------------------
# Logging — structured logging replaces bare print() calls so that log
# level, format, and destination can be controlled centrally.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application factory & Security Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)

# SECURITY (FINDING-002): Secure cryptographic secret key configured via
# environment variable with a cryptographically random fallback.
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())

init_db()

# SECURITY (FINDING-008): Rate limiting configured for expensive scanning routes
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

@app.errorhandler(429)
def ratelimit_handler(e):
    """Return clean, sanitized JSON response on rate limit breach."""
    return jsonify({
        "target": "",
        "status": "error",
        "message": "Rate limit exceeded. Please wait before initiating another scan.",
        "ports": []
    }), 429


# ---------------------------------------------------------------------------
# SECURITY: HTTP response-header hook (FINDING-003, FINDING-010, FINDING-012, DAST-P01)
#
# Applied to every response so that browsers receive the correct security
# policy regardless of which endpoint generated the response.
#
# CSP is constructed to be 100% self-contained without external CDN dependencies:
#   - style-src  : local CSS only
#   - font-src   : local fonts / native font stack only
#   - script-src : local JS only — no inline scripts, no eval()
#   - connect-src: same-origin only (all fetch() calls target the local API)
#   - img-src    : same-origin + data: URIs (CSS backgrounds may use data:)
#   - object-src : none  (no Flash/plugins)
#   - base-uri   : self  (prevent base-tag injection attacks)
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    """Attach security headers to every outgoing response."""
    response.headers["Server"] = "Aegis-Scanner"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self'; "
        "font-src 'self' data:; "
        "script-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self';"
    )
    # Prevent browsers and intermediate caches from storing API responses,
    # which may contain sensitive scan data (FINDING-012).
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response

@app.route("/")
def index():
    """
    Renders the main page of the Network Security Scanner.
    """
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
@limiter.limit("10 per minute")
def run_scan():
    """
    POST API endpoint to trigger a scan on the target.
    Expects JSON: { "target": "127.0.0.1" }
    Analyzes risks, saves findings in the database, and returns results.
    """
    try:
        # Verify request content type
        if not request.is_json:
            return jsonify({
                "target": "",
                "status": "error",
                "message": "Invalid request format. Content-Type must be application/json.",
                "ports": []
            }), 400

        # DAST-A01: Safely parse JSON and handle malformed JSON syntax gracefully
        try:
            data = request.get_json(silent=True)
        except Exception:
            data = None

        if data is None or not isinstance(data, dict):
            return jsonify({
                "target": "",
                "status": "error",
                "message": "Invalid JSON format in request body.",
                "ports": []
            }), 400

        target = data.get("target")

        if not target:
            return jsonify({
                "target": "",
                "status": "error",
                "message": "Target parameter is required.",
                "ports": []
            }), 400
            
        # Perform scan (scanner.py takes care of target validation and error containment)
        results = scan_target(target)
        
        if results.get("status") == "error":
            return jsonify(results), 400
            
        # Perform Risk Analysis on the detected ports
        ports_list = results.get("ports", [])
        analyzed_ports = []
        
        for p in ports_list:
            analysis = analyze_port(p["port"], p["service"])
            # Merge state and protocol details back into the port finding
            analysis["protocol"] = p.get("protocol", "tcp")
            analysis["state"] = p.get("state", "open")
            analyzed_ports.append(analysis)
            
        # Sort ports by port number
        analyzed_ports.sort(key=lambda x: x["port"])
        results["ports"] = analyzed_ports
        
        # Calculate overall risk
        overall_risk = calculate_overall_risk(analyzed_ports)
        results["overall_risk"] = overall_risk
        
        # Save to SQLite database
        try:
            scan_id = save_scan_results(
                target=results["target"],
                overall_risk=overall_risk,
                open_port_count=len(analyzed_ports),
                ports=analyzed_ports
            )
            results["scan_id"] = scan_id
        except Exception as db_err:
            # A successful scan must be persisted before it is reported as
            # successful. Keep implementation details out of the response.
            logger.error("Database save error for target '%s': %s", results.get("target", ""), db_err)
            return jsonify({
                "target": results["target"],
                "status": "error",
                "message": "Scan completed, but its results could not be saved.",
                "ports": []
            }), 500
            
        return jsonify(results), 200
        
    except Exception as e:
        # Catch any system-level anomalies to ensure Python stack traces never leak to client
        logger.exception("Unexpected error in /api/scan")
        return jsonify({
            "target": "",
            "status": "error",
            "message": "An unexpected server error occurred.",
            "ports": []
        }), 500

@app.route("/api/history", methods=["GET"])
def history_list():
    """
    GET API endpoint to retrieve the list of historical scans.
    Returns: JSON array of historical scans.
    """
    try:
        scans = get_scan_history()
        return jsonify(scans), 200
    except Exception:
        logger.exception("Error fetching scan history")
        return jsonify({
            "status": "error",
            "message": "Failed to retrieve scan history from database."
        }), 500

@app.route("/api/history", methods=["DELETE"])
def clear_history():
    """
    DELETE API endpoint to clear all historical scans and findings.
    Returns: JSON confirmation.
    """
    try:
        clear_scan_history()
        return jsonify({
            "status": "success",
            "message": "Scan history cleared successfully."
        }), 200
    except Exception:
        logger.exception("Error clearing scan history")
        return jsonify({
            "status": "error",
            "message": "Failed to clear scan history from database."
        }), 500

@app.route("/api/scan/<int:scan_id>", methods=["GET"])
def scan_details(scan_id):
    """Return the saved metadata and findings for one scan."""
    try:
        scan = get_scan_details(scan_id)
        if scan is None:
            return jsonify({"status": "error", "message": "Scan not found."}), 404
        return jsonify(scan), 200
    except Exception as error:
        logger.exception("Error fetching details for scan_id=%s", scan_id)
        return jsonify({"status": "error", "message": "Failed to retrieve scan details."}), 500

@app.route("/api/stats", methods=["GET"])
def dashboard_stats():
    """Return database-backed dashboard statistics."""
    try:
        return jsonify(get_dashboard_stats()), 200
    except Exception as error:
        logger.exception("Error fetching dashboard statistics")
        return jsonify({"status": "error", "message": "Failed to retrieve dashboard statistics."}), 500

@app.route("/api/scan/<int:scan_id>/export", methods=["GET"])
def export_scan_report(scan_id):
    """Generate a plain-text report from the persisted scan record."""
    try:
        scan = get_scan_details(scan_id)
        if scan is None:
            return jsonify({"status": "error", "message": "Scan not found."}), 404

        lines = [
            "AEGIS PORT SCANNER REPORT",
            "=" * 26,
            f"Scan ID: {scan['id']}",
            f"Target: {scan['target']}",
            f"Timestamp: {scan['scan_time']}",
            f"Overall risk: {scan['overall_risk']}",
            f"Open ports: {scan['open_port_count']}",
            "",
            "FINDINGS",
            "-" * 26,
        ]
        for finding in scan["ports"]:
            lines.extend([
                f"Port: {finding['port']}/{finding['protocol']} ({finding['state']})",
                f"Service: {finding['service']}",
                f"Risk: {finding['risk']}",
                f"Reason: {finding['reason']}",
                "",
            ])
        if not scan["ports"]:
            lines.append("No open TCP ports were recorded.")

        return Response(
            "\n".join(lines),
            mimetype="text/plain",
            headers={"Content-Disposition": f"attachment; filename=aegis-scan-{scan_id}.txt"},
        )
    except Exception as error:
        logger.exception("Error exporting report for scan_id=%s", scan_id)
        return jsonify({"status": "error", "message": "Failed to export scan report."}), 500

if __name__ == "__main__":
    # SECURITY (FINDING-001): debug mode must default to False so that the
    # Werkzeug interactive debugger is never exposed unintentionally.
    # Set FLASK_DEBUG=true in the environment to enable it explicitly during
    # local development when you need the reloader and step-through debugger.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)
