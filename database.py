import os
import sqlite3
from datetime import datetime

# Define database file path in the instance directory (Flask convention)
INSTANCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)
DB_PATH = os.path.join(INSTANCE_DIR, "aegis_scanner.db")

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
                open_port_count INTEGER NOT NULL
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
        
        conn.commit()
    finally:
        conn.close()

def save_scan_results(target, overall_risk, open_port_count, ports):
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
            INSERT INTO scans (target, scan_time, overall_risk, open_port_count)
            VALUES (?, ?, ?, ?)
        """, (target, timestamp, overall_risk, open_port_count))
        
        scan_id = cursor.lastrowid
        
        # Insert detail records (ports)
        for p in ports:
            cursor.execute("""
                INSERT INTO scan_results (scan_id, port, protocol, state, service, risk, risk_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                int(p["port"]),
                p.get("protocol", "tcp"),
                p.get("state", "open"),
                p.get("service", "unknown"),
                p.get("risk", "LOW"),
                p.get("reason", "")
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
            SELECT id, target, scan_time, overall_risk, open_port_count 
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
            SELECT id, target, scan_time, overall_risk, open_port_count 
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
        
        scan_data["ports"] = []
        for row in port_rows:
            port_dict = dict(row)
            # Rename risk_reason key back to 'reason' to match standard JSON formatting
            port_dict["reason"] = port_dict.pop("risk_reason")
            scan_data["ports"].append(port_dict)
            
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
        cursor.execute("DELETE FROM scan_results;")
        cursor.execute("DELETE FROM scans;")
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

