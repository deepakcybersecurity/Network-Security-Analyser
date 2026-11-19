import os
import sqlite3
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from risk_analyzer import calculate_security_score, get_remediation_guidance
from service_fingerprints import get_service_fingerprint

# Define database file path in the instance directory (Flask convention)
INSTANCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DB_PATH = os.environ.get("DATABASE_PATH", os.path.join(INSTANCE_DIR, "aegis_scanner.db"))

def get_db_connection():
    """
    Establishes a connection to the SQLite database.
    Enforces foreign keys and returns dictionary-accessible rows.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    """
    Initializes the database schema if tables do not exist.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Create 'scans' table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_time TEXT NOT NULL,
                overall_risk TEXT NOT NULL,
                open_port_count INTEGER NOT NULL,
                profile_id TEXT NOT NULL DEFAULT 'quick'
            );
        """)
        
        # Create 'scan_results' table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                service TEXT NOT NULL,
                risk TEXT NOT NULL,
                risk_reason TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            );
        """)
        
        # Create index on scan_id for fast joins
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id);")

        # Create 'ai_analyses' table for post-scan AI Security Analyst reports
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL UNIQUE,
                analysis_json TEXT NOT NULL,
                model TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_analyses_scan_id ON ai_analyses(scan_id);")

        # Create 'copilot_conversations' table for AI Copilot chat sessions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS copilot_conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                scan_id INTEGER,
                target TEXT NOT NULL DEFAULT '127.0.0.1',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE SET NULL
            );
        """)
        cursor.execute("PRAGMA table_info(copilot_conversations);")
        conv_cols = [c[1] for c in cursor.fetchall()]
        if "target" not in conv_cols:
            cursor.execute("ALTER TABLE copilot_conversations ADD COLUMN target TEXT DEFAULT '127.0.0.1';")

        # Create 'copilot_messages' table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS copilot_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                command_card_json TEXT,
                execution_id INTEGER,
                created_at TEXT NOT NULL,
                FOREIGN KEY (conversation_id) REFERENCES copilot_conversations (id) ON DELETE CASCADE
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_copilot_messages_conv ON copilot_messages(conversation_id);")

        # Create 'command_executions' table for audit trail & results tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS command_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                conversation_id INTEGER,
                tool TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                command_str TEXT NOT NULL,
                arguments_json TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                start_time TEXT,
                end_time TEXT,
                exit_code INTEGER,
                raw_output TEXT,
                parsed_findings_json TEXT,
                ai_analysis_json TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE SET NULL,
                FOREIGN KEY (conversation_id) REFERENCES copilot_conversations (id) ON DELETE SET NULL
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_command_executions_scan ON command_executions(scan_id);")

        # Upgrade databases created before scan profiles were introduced.
        scan_columns = {row[1] for row in cursor.execute("PRAGMA table_info(scans)").fetchall()}
        if "profile_id" not in scan_columns:
            cursor.execute("ALTER TABLE scans ADD COLUMN profile_id TEXT NOT NULL DEFAULT 'quick'")
        
        conn.commit()
    finally:
        conn.close()

def save_scan_results(target, overall_risk, open_port_count, ports, profile_id="quick"):
    """
    Saves scan results to the database under a transaction.
    Returns: The inserted scan_id (int) or None on failure.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Current formatted timestamp, e.g. "10 August 2026, 20:15"
        now = datetime.now()
        timestamp = now.strftime("%d %B %Y, %H:%M")
        
        # Insert master scan record
        cursor.execute("""
            INSERT INTO scans (target, scan_time, overall_risk, open_port_count, profile_id)
            VALUES (?, ?, ?, ?, ?)
        """, (target, timestamp, overall_risk, open_port_count, profile_id))
        
        scan_id = cursor.lastrowid
        
        # Insert detail records (ports)
        for p in ports:
            cursor.execute("""
                INSERT INTO scan_results (scan_id, port, protocol, state, service, risk, risk_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                int(p["port"]),
                p.get("protocol") or "tcp",
                p.get("state") or "open",
                p.get("service") or "unknown",
                p.get("risk") or "LOW",
                p.get("reason") or ""
            ))
            
        conn.commit()
        return scan_id
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_scan_history():
    """
    Retrieves all scan summaries sorted by most recent first.
    Returns: A list of dicts.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, target, scan_time, overall_risk, open_port_count, profile_id
            FROM scans 
            ORDER BY id DESC
        """)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_scan_details(scan_id):
    """
    Retrieves full details of a specific scan, including individual port findings.
    Returns: A dict or None if scan_id not found.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Retrieve main scan metadata
        cursor.execute("""
            SELECT id, target, scan_time, overall_risk, open_port_count, profile_id
            FROM scans 
            WHERE id = ?
        """, (scan_id,))
        scan_row = cursor.fetchone()
        
        if not scan_row:
            return None
            
        scan_data = dict(scan_row)
        
        # Retrieve related ports findings
        cursor.execute("""
            SELECT port, protocol, state, service, risk, risk_reason
            FROM scan_results
            WHERE scan_id = ?
            ORDER BY port ASC
        """, (scan_id,))
        port_rows = cursor.fetchall()
        
        profile_id = scan_data.get("profile_id", "quick")
        scan_data["ports"] = []
        for row in port_rows:
            port_dict = dict(row)
            # Rename risk_reason key back to 'reason' to match standard JSON formatting
            port_dict["reason"] = port_dict.pop("risk_reason")
            port_dict["remediation"] = get_remediation_guidance(port_dict.get("port"), port_dict.get("service"))
            port_dict["fingerprint"] = get_service_fingerprint(
                port_dict.get("port"),
                port_dict.get("service"),
                profile_id=profile_id,
                deterministic_risk=port_dict.get("risk", "LOW")
            )
            scan_data["ports"].append(port_dict)

        scan_data["security_score"] = calculate_security_score(scan_data["ports"], scan_status="success")
            
        return scan_data
    finally:
        conn.close()

def get_dashboard_stats():
    """
    Queries SQLite database to dynamically calculate total scans, total open ports,
    and frequency of findings by risk level.
    Returns: A dict.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # 1. Total Scans
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]
        
        # 2. Total Open Ports
        cursor.execute("SELECT COUNT(*) FROM scan_results")
        total_open_ports = cursor.fetchone()[0]
        
        # 3. High Risk Ports Count
        cursor.execute("SELECT COUNT(*) FROM scan_results WHERE risk = 'HIGH'")
        high_risk_count = cursor.fetchone()[0]
        
        # 4. Medium Risk Ports Count
        cursor.execute("SELECT COUNT(*) FROM scan_results WHERE risk = 'MEDIUM'")
        medium_risk_count = cursor.fetchone()[0]
        
        # 5. Low Risk Ports Count
        cursor.execute("SELECT COUNT(*) FROM scan_results WHERE risk = 'LOW'")
        low_risk_count = cursor.fetchone()[0]
        
        return {
            "total_scans": total_scans,
            "total_open_ports": total_open_ports,
            "high_risk_count": high_risk_count,
            "medium_risk_count": medium_risk_count,
            "low_risk_count": low_risk_count
        }
    finally:
        conn.close()

def clear_scan_history():
    """
    Clears all saved scans and related port findings under a transaction.
    Returns: True on success, raises Exception on failure.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM command_executions;")
        cursor.execute("DELETE FROM copilot_messages;")
        cursor.execute("DELETE FROM copilot_conversations;")
        cursor.execute("DELETE FROM ai_analyses;")
        cursor.execute("DELETE FROM scan_results;")
        cursor.execute("DELETE FROM scans;")
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def save_ai_analysis(scan_id, analysis_data, model="gpt-4o-mini"):
    """
    Saves an AI security analysis for a scan under a transaction.
    """
    import json
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now = datetime.now().strftime("%d %B %Y, %H:%M")
        analysis_str = json.dumps(analysis_data)
        cursor.execute("""
            INSERT INTO ai_analyses (scan_id, analysis_json, model, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                analysis_json = excluded.analysis_json,
                model = excluded.model,
                created_at = excluded.created_at;
        """, (scan_id, analysis_str, model, now))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_ai_analysis(scan_id):
    """
    Retrieves the cached AI analysis for a scan_id if it exists.
    Returns: dict with analysis, model, created_at, or None.
    """
    import json
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT scan_id, analysis_json, model, created_at
            FROM ai_analyses
            WHERE scan_id = ?
        """, (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "scan_id": row["scan_id"],
            "analysis": json.loads(row["analysis_json"]),
            "model": row["model"],
            "created_at": row["created_at"]
        }
    finally:
        conn.close()

def get_visualizations_data():
    """
    Retrieves aggregated statistical datasets for dashboard visualizations:
    1. Risk severity distribution (high, medium, low finding counts and percentages)
    2. Most frequently scanned targets (top 5 targets by scan count)
    3. Scan activity timeline (scans grouped chronologically by date)
    4. Overall database summary metrics
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # 1. Total counts
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT target) FROM scans")
        unique_targets = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_results")
        total_open_ports = cursor.fetchone()[0]

        # 2. Risk severity distribution
        cursor.execute("""
            SELECT risk, COUNT(*) as count
            FROM scan_results
            GROUP BY risk
        """)
        risk_counts = {row["risk"].upper(): row["count"] for row in cursor.fetchall()}
        high = risk_counts.get("HIGH", 0)
        med = risk_counts.get("MEDIUM", 0)
        low = risk_counts.get("LOW", 0)
        total_findings = high + med + low

        pct_high = round((high / total_findings * 100), 1) if total_findings > 0 else 0.0
        pct_med = round((med / total_findings * 100), 1) if total_findings > 0 else 0.0
        if total_findings == 0 or low == 0:
            pct_low = 0.0
        else:
            pct_low = max(round((100 - pct_high - pct_med), 1), 0.0)

        risk_distribution = {
            "high": high,
            "medium": med,
            "low": low,
            "total": total_findings,
            "unit": "discovered open port findings",
            "percentages": {
                "high": pct_high,
                "medium": pct_med,
                "low": pct_low
            }
        }

        # 3. Top scanned targets (up to 5)
        cursor.execute("""
            SELECT target, COUNT(*) as scan_count, MAX(overall_risk) as latest_risk
            FROM scans
            GROUP BY target
            ORDER BY scan_count DESC, id DESC
            LIMIT 5
        """)
        top_targets = []
        for row in cursor.fetchall():
            top_targets.append({
                "target": row["target"],
                "scan_count": row["scan_count"],
                "latest_risk": row["latest_risk"]
            })

        # 4. Scan activity timeline (chronological scans grouped by date)
        cursor.execute("""
            SELECT scan_time
            FROM scans
            ORDER BY id ASC
        """)
        scan_rows = cursor.fetchall()
        timeline_map = {}
        for row in scan_rows:
            raw_time = row["scan_time"]
            # e.g. "21 October 2026, 20:15" -> extract "21 October 2026"
            parts = raw_time.split(",")
            date_label = parts[0].strip() if parts else raw_time
            timeline_map[date_label] = timeline_map.get(date_label, 0) + 1

        activity_timeline = [
            {"date": date_lbl, "scan_count": count}
            for date_lbl, count in timeline_map.items()
        ]

        return {
            "summary": {
                "total_scans": total_scans,
                "unique_targets": unique_targets,
                "total_open_ports": total_open_ports
            },
            "risk_distribution": risk_distribution,
            "top_targets": top_targets,
            "activity_timeline": activity_timeline
        }
    finally:
        conn.close()


# ============================================================================
# AI COPILOT CONVERSATIONS & COMMAND EXECUTIONS ACCESS LAYER
# ============================================================================

def create_copilot_conversation(title: str, scan_id: Optional[int] = None, target: str = "127.0.0.1") -> int:
    """Creates a new Copilot chat conversation thread."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now = datetime.now().strftime("%d %B %Y, %H:%M")
        cursor.execute("""
            INSERT INTO copilot_conversations (title, scan_id, target, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (title[:80], scan_id, target or "127.0.0.1", now, now))
        conv_id = cursor.lastrowid
        conn.commit()
        return conv_id
    finally:
        conn.close()


def update_copilot_conversation_target(conversation_id: int, target: str, scan_id: Optional[int] = None) -> None:
    """Updates the active bound target (and optional scan_id) of a conversation thread."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now = datetime.now().strftime("%d %B %Y, %H:%M")
        if scan_id is not None:
            cursor.execute("""
                UPDATE copilot_conversations
                SET target = ?, scan_id = ?, updated_at = ?
                WHERE id = ?
            """, (target, scan_id, now, conversation_id))
        else:
            cursor.execute("""
                UPDATE copilot_conversations
                SET target = ?, updated_at = ?
                WHERE id = ?
            """, (target, now, conversation_id))
        conn.commit()
    finally:
        conn.close()


def get_copilot_conversations() -> List[Dict[str, Any]]:
    """Retrieves all Copilot conversation threads, newest first."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, title, scan_id, target, created_at, updated_at
            FROM copilot_conversations
            ORDER BY id DESC
        """)
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()


def get_copilot_conversation(conversation_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a conversation thread with its chronological messages."""
    import json
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, title, scan_id, target, created_at, updated_at
            FROM copilot_conversations
            WHERE id = ?
        """, (conversation_id,))
        conv_row = cursor.fetchone()
        if not conv_row:
            return None

        conv_data = dict(conv_row)

        cursor.execute("""
            SELECT id, conversation_id, role, content, command_card_json, execution_id, created_at
            FROM copilot_messages
            WHERE conversation_id = ?
            ORDER BY id ASC
        """, (conversation_id,))
        msg_rows = cursor.fetchall()

        messages = []
        for r in msg_rows:
            m = dict(r)
            if m.get("command_card_json"):
                try:
                    m["command_card"] = json.loads(m["command_card_json"])
                except Exception:
                    m["command_card"] = None
            else:
                m["command_card"] = None
            messages.append(m)

        conv_data["messages"] = messages
        return conv_data
    finally:
        conn.close()


def save_copilot_message(
    conversation_id: int,
    role: str,
    content: str,
    command_card: Optional[Dict[str, Any]] = None,
    execution_id: Optional[int] = None
) -> int:
    """Saves a message in a conversation thread and updates the thread timestamp."""
    import json
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now = datetime.now().strftime("%d %B %Y, %H:%M")
        cmd_json = json.dumps(command_card) if command_card else None

        cursor.execute("""
            INSERT INTO copilot_messages (conversation_id, role, content, command_card_json, execution_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (conversation_id, role, content, cmd_json, execution_id, now))
        msg_id = cursor.lastrowid

        cursor.execute("""
            UPDATE copilot_conversations
            SET updated_at = ?
            WHERE id = ?
        """, (now, conversation_id))

        conn.commit()
        return msg_id
    finally:
        conn.close()


def create_command_execution(
    tool: str,
    operation_id: str,
    command_str: str,
    arguments: List[str],
    target: str,
    scan_id: Optional[int] = None,
    conversation_id: Optional[int] = None
) -> int:
    """Inserts a command execution record into the audit log with 'pending' status."""
    import json
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now = datetime.now().strftime("%d %B %Y, %H:%M:%S")
        args_json = json.dumps(arguments)

        cursor.execute("""
            INSERT INTO command_executions (
                scan_id, conversation_id, tool, operation_id, command_str,
                arguments_json, target, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        """, (scan_id, conversation_id, tool, operation_id, command_str, args_json, target, now))
        exec_id = cursor.lastrowid
        conn.commit()
        return exec_id
    finally:
        conn.close()


def update_command_execution(
    execution_id: int,
    status: Optional[str] = None,
    raw_output: Optional[str] = None,
    exit_code: Optional[int] = None,
    parsed_findings: Optional[Dict[str, Any]] = None,
    ai_analysis: Optional[Dict[str, Any]] = None,
    error_message: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None
) -> None:
    """Updates status, raw output, parsed findings, and AI explanation of a command execution."""
    import json
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        parsed_json = json.dumps(parsed_findings) if parsed_findings is not None else None
        ai_json = json.dumps(ai_analysis) if ai_analysis is not None else None

        cursor.execute("""
            UPDATE command_executions
            SET status = COALESCE(?, status),
                raw_output = COALESCE(?, raw_output),
                exit_code = COALESCE(?, exit_code),
                parsed_findings_json = COALESCE(?, parsed_findings_json),
                ai_analysis_json = COALESCE(?, ai_analysis_json),
                error_message = COALESCE(?, error_message),
                start_time = COALESCE(?, start_time),
                end_time = COALESCE(?, end_time)
            WHERE id = ?
        """, (
            status,
            raw_output,
            exit_code,
            parsed_json,
            ai_json,
            error_message,
            start_time,
            end_time,
            execution_id
        ))
        conn.commit()
    finally:
        conn.close()


def get_command_execution(execution_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves full details of a specific command execution."""
    import json
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, scan_id, conversation_id, tool, operation_id, command_str,
                   arguments_json, target, status, start_time, end_time, exit_code,
                   raw_output, parsed_findings_json, ai_analysis_json, error_message, created_at
            FROM command_executions
            WHERE id = ?
        """, (execution_id,))
        row = cursor.fetchone()
        if not row:
            return None

        d = dict(row)
        if d.get("arguments_json"):
            try:
                d["arguments"] = json.loads(d["arguments_json"])
            except Exception:
                d["arguments"] = []
        if d.get("parsed_findings_json"):
            try:
                d["parsed_findings"] = json.loads(d["parsed_findings_json"])
            except Exception:
                d["parsed_findings"] = None
        if d.get("ai_analysis_json"):
            try:
                d["ai_analysis"] = json.loads(d["ai_analysis_json"])
            except Exception:
                d["ai_analysis"] = None
        return d
    finally:
        conn.close()


def get_command_executions_for_scan(scan_id: int) -> List[Dict[str, Any]]:
    """Retrieves all completed command executions tied to a scan assessment."""
    import json
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, scan_id, conversation_id, tool, operation_id, command_str,
                   arguments_json, target, status, start_time, end_time, exit_code,
                   raw_output, parsed_findings_json, ai_analysis_json, error_message, created_at
            FROM command_executions
            WHERE scan_id = ? AND status = 'completed'
            ORDER BY id ASC
        """, (scan_id,))
        rows = cursor.fetchall()
        results = []
        for r in rows:
            d = dict(r)
            if d.get("parsed_findings_json"):
                try:
                    d["parsed_findings"] = json.loads(d["parsed_findings_json"])
                except Exception:
                    d["parsed_findings"] = None
            if d.get("ai_analysis_json"):
                try:
                    d["ai_analysis"] = json.loads(d["ai_analysis_json"])
                except Exception:
                    d["ai_analysis"] = None
            results.append(d)
        return results
    finally:
        conn.close()




