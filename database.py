import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_NAME = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "forensic.db"))


def get_conn():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            block_index   INTEGER PRIMARY KEY,
            timestamp     TEXT,
            evidence_id   TEXT,
            action        TEXT,
            from_user     TEXT,
            to_user       TEXT,
            evidence_hash TEXT,
            details       TEXT,
            previous_hash TEXT,
            hash          TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id    TEXT PRIMARY KEY,
            filename       TEXT,
            filepath       TEXT,
            sha256         TEXT,
            current_holder TEXT,
            description    TEXT,
            uploaded_at    TEXT,
            size_bytes     INTEGER
        )
    """)
    conn.commit()
    conn.close()


def save_block(block):
    conn = get_conn()
    conn.execute(
        "INSERT INTO blocks VALUES (?,?,?,?,?,?,?,?,?,?)",
        (block.index, block.timestamp, block.evidence_id, block.action,
         block.from_user, block.to_user, block.evidence_hash,
         block.details, block.previous_hash, block.hash),
    )
    conn.commit()
    conn.close()


def load_blocks():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM blocks ORDER BY block_index").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_evidence(evidence_id, filename, stored_name, sha256, holder,
                  description, uploaded_at, size_bytes):
    conn = get_conn()
    conn.execute(
        "INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?)",
        (evidence_id, filename, stored_name, sha256, holder, description,
         uploaded_at, size_bytes),
    )
    conn.commit()
    conn.close()


def get_all_evidence():
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM evidence ORDER BY uploaded_at DESC, evidence_id DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_evidence():
    conn = get_conn()
    n = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    conn.close()
    return n


def get_evidence(evidence_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM evidence WHERE evidence_id=?",
                       (evidence_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_holder(evidence_id, new_holder):
    conn = get_conn()
    conn.execute("UPDATE evidence SET current_holder=? WHERE evidence_id=?",
                 (new_holder, evidence_id))
    conn.commit()
    conn.close()


# ---- Demo helpers (used by the Tamper Lab page) ----

def tamper_block_directly(block_index):
    """Simulate an attacker editing the database file directly."""
    conn = get_conn()
    conn.execute(
        "UPDATE blocks SET details = details || ' [EDITED BY ATTACKER]' "
        "WHERE block_index=?", (block_index,))
    conn.commit()
    conn.close()


def reset_all():
    conn = get_conn()
    conn.execute("DELETE FROM blocks")
    conn.execute("DELETE FROM evidence")
    conn.commit()
    conn.close()
