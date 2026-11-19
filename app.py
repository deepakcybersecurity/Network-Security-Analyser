import sys
import os
import re
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

def _load_env_file():
    """Load configuration variables from local .env if present."""
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.isfile(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, val = line.split("=", 1)
                        key = key.strip()
                        val = val.strip().strip("'\"")
                        if key and key not in os.environ:
                            os.environ[key] = val
        except Exception as e:
            logging.getLogger(__name__).warning("Could not read .env file: %s", e)

_load_env_file()

from ai import AIAnalystError, analyze_scan
from ai.copilot import analyze_command_findings, generate_copilot_response
from ai_assistant import AssistantError, recommend_scan_profile
from command_registry import (
    COMMAND_REGISTRY,
    get_supported_operations,
    validate_execution_plan,
)
from command_runner import (
    ACTIVE_PROCESSES,
    cancel_command_execution,
    run_command_in_background,
)
from comparator import (
    ComparisonError,
    ScanNotFoundError,
    TargetMismatchError,
    compare_scans,
)
from database import (
    clear_scan_history,
    create_command_execution,
    create_copilot_conversation,
    get_ai_analysis,
    get_command_execution,
    get_command_executions_for_scan,
    get_copilot_conversation,
    get_copilot_conversations,
    get_dashboard_stats,
    get_scan_details,
    get_scan_history,
    get_visualizations_data,
    init_db,
    save_ai_analysis,
    save_copilot_message,
    save_scan_results,
    update_command_execution,
    update_copilot_conversation_target,
)
from export_service import dispatch_export
from risk_analyzer import analyze_port, calculate_overall_risk, calculate_security_score
from scanner import SCAN_PROFILES, scan_target, validate_target
from service_fingerprints import get_service_fingerprint

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
# environment variable with a cryptographically random fallback if unset or placeholder.
raw_secret = os.environ.get("SECRET_KEY", "").strip()
if not raw_secret or raw_secret == "replace_with_a_long_random_secret":  # nosec B105
    app.secret_key = os.urandom(32).hex()
else:
    app.secret_key = raw_secret

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
        profile_id = data.get("profile_id", "quick")

        if not target:
            return jsonify({
                "target": "",
                "status": "error",
                "message": "Target parameter is required.",
                "ports": []
            }), 400

        if not isinstance(profile_id, str) or profile_id not in SCAN_PROFILES:
            return jsonify({
                "target": "",
                "status": "error",
                "message": "Unknown scan profile.",
                "ports": []
            }), 400
            
        # Perform scan using a reviewed profile selected by the user.
        results = scan_target(target, profile_id)
        
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
            analysis["fingerprint"] = get_service_fingerprint(
                analysis["port"],
                analysis.get("service"),
                profile_id=profile_id,
                deterministic_risk=analysis.get("risk", "LOW")
            )
            analyzed_ports.append(analysis)
            
        # Sort ports by port number
        analyzed_ports.sort(key=lambda x: x["port"])
        results["ports"] = analyzed_ports
        results["scan_profile"] = {
            "profile_id": profile_id,
            "name": SCAN_PROFILES[profile_id]["name"],
            "flags": SCAN_PROFILES[profile_id]["flags"],
        }
        
        # Calculate overall risk
        overall_risk = calculate_overall_risk(analyzed_ports)
        results["overall_risk"] = overall_risk

        # Calculate deterministic security score
        security_score = calculate_security_score(analyzed_ports, scan_status=results.get("status", "success"))
        results["security_score"] = security_score
        
        # Save to SQLite database
        try:
            scan_id = save_scan_results(
                target=results["target"],
                overall_risk=overall_risk,
                open_port_count=len(analyzed_ports),
                ports=analyzed_ports,
                profile_id=profile_id,
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

@app.route("/api/assistant/recommend", methods=["POST"])
@limiter.limit("20 per minute")
def assistant_recommendation():
    """Return an OpenAI suggestion mapped to a locally approved scan profile."""
    if not request.is_json:
        return jsonify({"status": "error", "message": "Content-Type must be application/json."}), 400

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Invalid JSON request body."}), 400

    need = data.get("need")
    if not isinstance(need, str) or not need.strip():
        return jsonify({"status": "error", "message": "Describe what you need to scan."}), 400
    if len(need) > 1200:
        return jsonify({"status": "error", "message": "Keep the scan goal under 1200 characters."}), 400

    try:
        recommendation = recommend_scan_profile(need.strip())
        return jsonify({"status": "success", "recommendation": recommendation}), 200
    except AssistantError as error:
        return jsonify({"status": "error", "message": str(error)}), 503
    except Exception:
        logger.exception("Unexpected error getting scan profile recommendation")
        return jsonify({"status": "error", "message": "The assistant is temporarily unavailable."}), 503


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
        profile = SCAN_PROFILES.get(scan.get("profile_id"), SCAN_PROFILES["quick"])
        scan["scan_profile"] = {
            "profile_id": scan.get("profile_id", "quick"),
            "name": profile["name"],
            "flags": profile["flags"],
        }
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

@app.route("/api/stats/visualizations", methods=["GET"])
def dashboard_visualizations():
    """Return database-backed aggregated datasets for visual risk charts."""
    try:
        return jsonify(get_visualizations_data()), 200
    except Exception:
        logger.exception("Error fetching visualization statistics")
        return jsonify({
            "status": "error",
            "message": "Failed to retrieve visualization statistics from database."
        }), 500

@app.route("/api/scan/compare", methods=["GET"])
@limiter.limit("30 per minute")
def compare_historical_scans():
    """
    Compare two historical scans for the same normalized target.
    Expects query parameters:
      - base_id & target_id  (or scan_a & scan_b)
    """
    scan_a_val = request.args.get("base_id") or request.args.get("scan_a")
    scan_b_val = request.args.get("target_id") or request.args.get("scan_b")

    if not scan_a_val or not scan_b_val:
        return jsonify({
            "status": "error",
            "message": "Two scan IDs are required for comparison (e.g. ?base_id=1&target_id=2)."
        }), 400

    try:
        scan_a_id = int(scan_a_val)
        scan_b_id = int(scan_b_val)
    except (ValueError, TypeError):
        return jsonify({
            "status": "error",
            "message": "Scan IDs must be valid integers."
        }), 400

    try:
        comparison = compare_scans(scan_a_id, scan_b_id)
        return jsonify(comparison), 200
    except ScanNotFoundError as not_found_err:
        return jsonify({
            "status": "error",
            "message": str(not_found_err)
        }), 404
    except TargetMismatchError as mismatch_err:
        return jsonify({
            "status": "error",
            "message": str(mismatch_err)
        }), 400
    except ComparisonError as comp_err:
        return jsonify({
            "status": "error",
            "message": str(comp_err)
        }), 400
    except Exception:
        logger.exception("Unexpected error comparing scans %s and %s", scan_a_val, scan_b_val)
        return jsonify({
            "status": "error",
            "message": "An unexpected error occurred while comparing the scans."
        }), 500

@app.route("/api/ai/analyze/<int:scan_id>", methods=["GET"])
def get_scan_ai_analysis(scan_id):
    """Retrieve existing cached AI security analysis for a scan."""
    try:
        cached = get_ai_analysis(scan_id)
        if not cached:
            return jsonify({
                "status": "not_found",
                "message": "No AI analysis found for this scan."
            }), 404
        return jsonify({
            "status": "success",
            "cached": True,
            "scan_id": scan_id,
            "analysis": cached["analysis"],
            "model": cached["model"],
            "created_at": cached["created_at"],
        }), 200
    except Exception:
        logger.exception("Error retrieving AI analysis for scan_id=%s", scan_id)
        return jsonify({
            "status": "error",
            "message": "Failed to retrieve AI analysis."
        }), 500


@app.route("/api/ai/analyze/<int:scan_id>", methods=["POST"])
@limiter.limit("20 per minute")
def run_scan_ai_analysis(scan_id):
    """
    Generate or retrieve an AI Security Analyst evaluation for a completed scan.
    Optionally accepts JSON: { "force_refresh": true } to re-generate.
    """
    try:
        scan = get_scan_details(scan_id)
        if scan is None:
            return jsonify({"status": "error", "message": "Scan not found."}), 404

        force_refresh = False
        if request.is_json:
            req_data = request.get_json(silent=True) or {}
            force_refresh = bool(req_data.get("force_refresh", False))

        # Check cache if not forcing refresh
        if not force_refresh:
            cached = get_ai_analysis(scan_id)
            if cached:
                return jsonify({
                    "status": "success",
                    "cached": True,
                    "scan_id": scan_id,
                    "analysis": cached["analysis"],
                    "model": cached["model"],
                    "created_at": cached["created_at"],
                }), 200

        # Attach profile metadata to scan context
        profile = SCAN_PROFILES.get(scan.get("profile_id"), SCAN_PROFILES["quick"])
        scan["scan_profile"] = {
            "profile_id": scan.get("profile_id", "quick"),
            "name": profile["name"],
            "flags": profile["flags"],
        }

        # Run AI analysis
        try:
            analysis = analyze_scan(scan)
        except AIAnalystError as err:
            return jsonify({"status": "error", "message": str(err)}), 503

        # Persist analysis in SQLite
        model_used = analysis.get("_model", "gpt-4o-mini")
        save_ai_analysis(scan_id, analysis, model=model_used)

        return jsonify({
            "status": "success",
            "cached": False,
            "scan_id": scan_id,
            "analysis": analysis,
            "model": model_used,
        }), 200

    except Exception:
        logger.exception("Unexpected error analyzing scan_id=%s", scan_id)
        return jsonify({
            "status": "error",
            "message": "An unexpected error occurred during AI assessment."
        }), 500


@app.route("/api/scan/<int:scan_id>/export", methods=["GET"])
def export_scan_report(scan_id):
    """
    Export scan report in requested format.
    Supports:
      - ?format=txt (default plain text report)
      - ?format=pdf (professional executive & technical report via ReportLab)
      - ?format=csv (structured tabular export with formula injection escaping)
      - ?format=json (standard schema version 1.0 JSON export)
    """
    format_type = request.args.get("format", "txt")
    return dispatch_export(scan_id, format_type)


# ============================================================================
# AI COPILOT API ENDPOINTS
# ============================================================================

@app.route("/api/copilot/operations", methods=["GET"])
def list_copilot_operations():
    """Returns the well-defined registry of supported diagnostic operations."""
    ops = get_supported_operations()
    return jsonify({
        "status": "success",
        "count": len(ops),
        "operations": ops
    }), 200


@app.route("/api/copilot/conversations", methods=["GET"])
def list_copilot_conversations():
    """Lists saved Copilot conversation threads."""
    return jsonify(get_copilot_conversations()), 200


@app.route("/api/copilot/conversation/<int:conversation_id>", methods=["GET"])
def get_single_copilot_conversation(conversation_id):
    """Retrieves a specific conversation thread and its message history."""
    conv = get_copilot_conversation(conversation_id)
    if not conv:
        return jsonify({"status": "error", "message": "Conversation not found."}), 404
    return jsonify({"status": "success", "conversation": conv}), 200


@app.route("/api/copilot/chat", methods=["POST"])
@limiter.limit("30 per minute")
def copilot_chat():
    """
    Natural-language endpoint for Aegis AI Copilot.
    Receives user query, active scan context, and returns an expert response
    along with an approved structured command card if appropriate.
    """
    data = request.get_json(silent=True) or {}
    user_msg = str(data.get("message", "")).strip()
    if not user_msg:
        return jsonify({"status": "error", "message": "Message content cannot be empty."}), 400
    if len(user_msg) > 3000:
        return jsonify({"status": "error", "message": "Message exceeds maximum allowed length (3000 characters)."}), 400

    conv_id = data.get("conversation_id")
    history_messages = []
    conv = None
    if conv_id:
        try:
            conv = get_copilot_conversation(int(conv_id))
            if conv:
                history_messages = [
                    {"role": m["role"], "content": m["content"]}
                    for m in conv.get("messages", [])
                ]
            else:
                conv_id = None
        except (ValueError, TypeError):
            conv_id = None

    # Check if user message explicitly specifies a target IP address
    explicit_target = None
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", user_msg)
    if ip_match:
        explicit_target = ip_match.group(0)

    active_scan = None
    if conv:
        # Existing conversation: preserve conversation's bound target unless user explicitly specifies a new target
        if explicit_target:
            update_copilot_conversation_target(conv["id"], explicit_target)
            active_scan = {"target": explicit_target}
        else:
            conv_scan_id = conv.get("scan_id")
            if conv_scan_id:
                try:
                    active_scan = get_scan_details(int(conv_scan_id))
                except Exception:
                    active_scan = None
            if not active_scan:
                conv_target = conv.get("target") or "127.0.0.1"
                active_scan = {"target": conv_target}
    else:
        # Starting new conversation: bind to scan_id or target provided
        scan_id = data.get("scan_id")
        if scan_id is not None:
            try:
                active_scan = get_scan_details(int(scan_id))
            except (ValueError, TypeError):
                active_scan = None

        target = explicit_target or (active_scan.get("target") if active_scan else None) or str(data.get("target", "127.0.0.1")).strip() or "127.0.0.1"
        if not active_scan:
            active_scan = {"target": target}

        title = user_msg[:40] + ("..." if len(user_msg) > 40 else "")
        conv_id = create_copilot_conversation(
            title=title,
            scan_id=active_scan.get("id") if (scan_id and active_scan) else None,
            target=active_scan.get("target", target)
        )

    # Save user message
    save_copilot_message(conv_id, role="user", content=user_msg)

    # Generate Copilot response
    copilot_result = generate_copilot_response(
        messages_history=history_messages,
        user_message=user_msg,
        active_scan_data=active_scan
    )

    reply_content = copilot_result.get("reply", "I have reviewed your request.")
    cmd_card = copilot_result.get("suggested_command")

    # Save assistant message with command card
    save_copilot_message(conv_id, role="assistant", content=reply_content, command_card=cmd_card)

    current_target = active_scan.get("target", "127.0.0.1") if active_scan else "127.0.0.1"
    current_scan_id = active_scan.get("id") if (active_scan and "id" in active_scan) else (conv.get("scan_id") if conv else None)

    return jsonify({
        "status": "success",
        "conversation_id": conv_id,
        "target": current_target,
        "scan_id": current_scan_id,
        "reply": reply_content,
        "command_card": cmd_card,
        "suggested_command": cmd_card,
        "model": copilot_result.get("model", "offline-expert-heuristic")
    }), 200


@app.route("/api/copilot/execute", methods=["POST"])
@limiter.limit("10 per minute")
def execute_copilot_command():
    """
    Executes an approved, validated command plan directly inside Aegis.
    Requires explicit operator confirmation and independently validates the plan
    against the command registry and target allowlist before execution.
    """
    import threading
    data = request.get_json(silent=True) or {}

    # 1. Require explicit user confirmation (Requirement 4C)
    if not data.get("confirmed"):
        return jsonify({
            "status": "error",
            "message": "Explicit user confirmation is required before running diagnostic commands."
        }), 400

    raw_plan = data.get("execution_plan") or data.get("plan")
    if not raw_plan or not isinstance(raw_plan, dict):
        return jsonify({"status": "error", "message": "Valid execution plan is required."}), 400

    target = str(data.get("target") or raw_plan.get("target", "")).strip()

    # 2. Strict target validation
    is_valid_tgt, sanitized_or_err = validate_target(target)
    if not is_valid_tgt:
        return jsonify({"status": "error", "message": f"Target validation failed: {sanitized_or_err}"}), 400

    target = sanitized_or_err

    # 3. Independent plan validation against registry
    is_valid_plan, validated_plan, plan_err = validate_execution_plan(raw_plan, target)
    if not is_valid_plan or not validated_plan:
        return jsonify({"status": "error", "message": plan_err or "Invalid execution plan."}), 400

    # 4. Enforce authorized target scope if tied to an existing scan
    scan_id = data.get("scan_id")
    if scan_id is not None:
        try:
            scan = get_scan_details(int(scan_id))
            if scan and scan.get("target"):
                scan_tgt = scan["target"].lower().strip()
                if scan_tgt != target.lower().strip():
                    return jsonify({
                        "status": "error",
                        "message": f"Scope mismatch: Command target '{target}' does not match assessment target '{scan['target']}'."
                    }), 400
        except (ValueError, TypeError):
            scan_id = None

    # 5. Check concurrency limit (max 2 active background tasks)
    if len(ACTIVE_PROCESSES) >= 2:
        return jsonify({
            "status": "error",
            "message": "A diagnostic operation is already executing. Please wait for completion or cancel it."
        }), 429

    conv_id = data.get("conversation_id")
    tool = validated_plan["tool"]
    operation_id = validated_plan["operation_id"]
    command_str = validated_plan["command_str"]
    arguments = validated_plan["arguments"]

    # 6. Insert audit trail record in SQLite
    exec_id = create_command_execution(
        tool=tool,
        operation_id=operation_id,
        command_str=command_str,
        arguments=arguments,
        target=target,
        scan_id=scan_id,
        conversation_id=conv_id
    )

    # 7. Launch execution in isolated background thread
    t = threading.Thread(
        target=run_command_in_background,
        args=(exec_id, validated_plan, update_command_execution, analyze_command_findings),
        daemon=True
    )
    t.start()

    return jsonify({
        "status": "started",
        "execution_id": exec_id,
        "tool": tool,
        "operation_id": operation_id,
        "command_str": command_str,
        "target": target
    }), 202


@app.route("/api/copilot/execution/<int:execution_id>", methods=["GET"])
def get_execution_status(execution_id):
    """Retrieves real-time status, terminal output, and parsed AI findings for an execution."""
    rec = get_command_execution(execution_id)
    if not rec:
        return jsonify({"status": "error", "message": "Command execution record not found."}), 404

    res_dict = dict(rec)
    res_dict["status"] = rec.get("status", "running")
    res_dict["execution"] = rec
    return jsonify(res_dict), 200


@app.route("/api/copilot/execution/<int:execution_id>/cancel", methods=["POST"])
def cancel_execution(execution_id):
    """Cooperatively cancels an active background execution."""
    cancelled = cancel_command_execution(execution_id)
    return jsonify({
        "status": "success",
        "cancelled": cancelled,
        "execution_id": execution_id
    }), 200

if __name__ == "__main__":
    # SECURITY (FINDING-001): debug mode must default to False so that the
    # Werkzeug interactive debugger is never exposed unintentionally.
    # Set FLASK_DEBUG=true in the environment to enable it explicitly during
    # local development when you need the reloader and step-through debugger.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)
