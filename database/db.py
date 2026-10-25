import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "shadow.db")

_db_initialized = False

def get_connection():
    global _db_initialized
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    if not _db_initialized:
        _db_initialized = True
        init_db_schema(conn)
    return conn

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    init_db_schema(conn)
    conn.close()

def init_db_schema(conn):
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sample_id TEXT UNIQUE,
            file_name TEXT,
            file_type TEXT,
            file_size INTEGER,
            md5 TEXT,
            sha1 TEXT,
            sha256 TEXT,
            risk_score INTEGER,
            verdict TEXT,
            confidence REAL,
            summary_json TEXT,
            details_json TEXT,
            iocs_json TEXT,
            mitre_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS known_hashes (
            hash_val TEXT PRIMARY KEY,
            family TEXT,
            verdict TEXT,
            notes TEXT
        )
    """)
    
    # Pre-populate known malware and clean hashes
    known_seeds = [
        ("44d88612fea8a8f36de82e1278abb02f", "WannaCry Dropper", "CRITICAL", "Ransomware signature match"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Empty File", "BENIGN", "Standard empty file"),
        ("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", "Cerberus Android Trojan", "CRITICAL", "Known banking stealer signature"),
        ("fedcba98765432100123456789abcdef", "Anubis Spyware", "CRITICAL", "Targeted SMS interception & overlay C2")
    ]
    cursor.executemany("INSERT OR IGNORE INTO known_hashes VALUES (?, ?, ?, ?)", known_seeds)
    conn.commit()

def save_scan(data):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO scans (
            sample_id, file_name, file_type, file_size, md5, sha1, sha256,
            risk_score, verdict, confidence, summary_json, details_json, iocs_json, mitre_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("sample_id"),
        data.get("file_name"),
        data.get("file_type"),
        data.get("file_size"),
        data.get("md5"),
        data.get("sha1"),
        data.get("sha256"),
        data.get("risk_score"),
        data.get("verdict"),
        data.get("confidence"),
        json.dumps(data.get("summary", {})),
        json.dumps(data.get("details", {})),
        json.dumps(data.get("iocs", [])),
        json.dumps(data.get("mitre", [])),
        datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()

def get_all_scans():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT sample_id, file_name, file_type, file_size, risk_score, verdict, confidence, created_at FROM scans ORDER BY id DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_scan_by_id(sample_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE sample_id = ?", (sample_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        result = dict(row)
        result["summary"] = json.loads(result["summary_json"]) if result["summary_json"] else {}
        result["details"] = json.loads(result["details_json"]) if result["details_json"] else {}
        result["iocs"] = json.loads(result["iocs_json"]) if result["iocs_json"] else []
        result["mitre"] = json.loads(result["mitre_json"]) if result["mitre_json"] else []
        return result
    return None

def lookup_hash(file_hash):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM known_hashes WHERE hash_val = ?", (file_hash.lower(),))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None
