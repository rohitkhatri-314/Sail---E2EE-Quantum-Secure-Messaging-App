"""
Local Encrypted / Isolated SQLite Database for Client Message History.
Each user maintains their own local database table storing:
- Peer username
- Sender
- Decrypted message content
- Timestamp
- Ratchet turn and message index
- Status (sent / received)
"""

import sqlite3
import os
from typing import List, Dict

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "messages.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS message_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            peer TEXT NOT NULL,
            sender TEXT NOT NULL,
            text TEXT NOT NULL,
            ts INTEGER NOT NULL,
            status TEXT NOT NULL,
            turn INTEGER DEFAULT 1,
            n INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

def save_message(owner: str, peer: str, sender: str, text: str, ts: int, status: str, turn: int = 1, n: int = 0):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO message_history (owner, peer, sender, text, ts, status, turn, n)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (owner, peer, sender, text, ts, status, turn, n))
    conn.commit()
    conn.close()

def get_history_for_peer(owner: str, peer: str) -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sender, peer, text, ts, status, turn, n
        FROM message_history
        WHERE owner = ? AND peer = ?
        ORDER BY ts ASC, id ASC
    """, (owner, peer))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_all_previews(owner: str) -> Dict[str, Dict]:
    """Returns the most recent message for each contact to populate chat list previews."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT peer, text, ts, sender
        FROM message_history
        WHERE owner = ?
        ORDER BY ts ASC, id ASC
    """, (owner,))
    rows = cursor.fetchall()
    conn.close()

    previews = {}
    for r in rows:
        previews[r["peer"]] = {"text": r["text"], "ts": r["ts"], "sender": r["sender"]}
    return previews
