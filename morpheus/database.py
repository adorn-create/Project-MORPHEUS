import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL,
  source TEXT,
  target TEXT,
  confidence REAL,
  evidence TEXT,
  response TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
"""

class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript(SCHEMA)

    def connect(self):
        return sqlite3.connect(self.path, check_same_thread=False)

    def add(self, event: dict):
        with self.connect() as db:
            db.execute("INSERT INTO events(timestamp,kind,severity,source,target,confidence,evidence,response) VALUES(:timestamp,:kind,:severity,:source,:target,:confidence,:evidence,:response)", event)

    def list_events(self, limit=200):
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            rows = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def count(self):
        with self.connect() as db:
            return db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
