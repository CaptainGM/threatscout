from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from threatscout.models import EnrichmentReport


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class Store:
    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    threat_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    report_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_scans_ioc ON scans(ioc);

                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    prefix TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used TEXT
                );

                CREATE TABLE IF NOT EXISTS webhooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    url TEXT NOT NULL,
                    token TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS webhook_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    webhook_id INTEGER NOT NULL,
                    scan_id INTEGER,
                    status TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS watchlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc TEXT NOT NULL UNIQUE,
                    ioc_type TEXT NOT NULL,
                    interval_hours INTEGER NOT NULL DEFAULT 24,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_score REAL,
                    last_risk TEXT,
                    last_checked TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )

    def save_scan(self, report: EnrichmentReport) -> int:
        payload = json.dumps(report.to_dict(), ensure_ascii=False)
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans (ioc, ioc_type, threat_score, risk_level, report_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    report.ioc,
                    report.ioc_type.value,
                    report.threat_score,
                    report.risk_level.value,
                    payload,
                    report.analyzed_at.isoformat(),
                ),
            )
            scan_id = int(cur.lastrowid)
        report.id = scan_id
        return scan_id

    def list_scans(self, limit: int = 50, q: str = "") -> list[dict[str, Any]]:
        sql = "SELECT id, ioc, ioc_type, threat_score, risk_level, created_at FROM scans"
        params: list[Any] = []
        if q:
            sql += " WHERE ioc LIKE ?"
            params.append(f"%{q}%")
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, report_json FROM scans WHERE id=?", (scan_id,)
            ).fetchone()
        if not row:
            return None
        data = json.loads(row["report_json"])
        data["id"] = row["id"]
        return data

    def stats(self, days: int = 30) -> dict[str, Any]:
        # Panel için özet: toplam, risk dağılımı, gün gün sayılar, en riskli ve en çok tarananlar
        since = (datetime.now(timezone.utc) - timedelta(days=days - 1)).date().isoformat()
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            levels = {
                row[0]: row[1]
                for row in conn.execute("SELECT risk_level, COUNT(*) FROM scans GROUP BY risk_level").fetchall()
            }
            daily = {
                row[0]: row[1]
                for row in conn.execute(
                    "SELECT substr(created_at, 1, 10) AS day, COUNT(*) FROM scans "
                    "WHERE substr(created_at, 1, 10) >= ? GROUP BY day",
                    (since,),
                ).fetchall()
            }
            top = conn.execute(
                "SELECT id, ioc, ioc_type, threat_score, risk_level, created_at FROM scans "
                "ORDER BY threat_score DESC, id DESC LIMIT 10"
            ).fetchall()
            most = conn.execute(
                "SELECT ioc, COUNT(*) AS n FROM scans GROUP BY ioc ORDER BY n DESC, ioc LIMIT 5"
            ).fetchall()
        return {
            "total": total,
            "levels": levels,
            "daily": daily,
            "since": since,
            "top": [dict(r) for r in top],
            "most": [dict(r) for r in most],
        }

    def create_api_key(self, name: str) -> str:
        raw = "ts_" + secrets.token_urlsafe(24)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO api_keys (name, key_hash, prefix, created_at) VALUES (?, ?, ?, ?)",
                (name, hash_key(raw), raw[:10], _now()),
            )
        return raw

    def list_api_keys(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, name, prefix, created_at, last_used FROM api_keys ORDER BY id DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_api_key(self, key_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM api_keys WHERE id=?", (key_id,))

    def valid_api_key(self, raw: str | None) -> bool:
        if not raw:
            return False
        digest = hash_key(raw)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id FROM api_keys WHERE key_hash=?", (digest,)
            ).fetchone()
            if not row:
                return False
            conn.execute(
                "UPDATE api_keys SET last_used=? WHERE id=?", (_now(), row["id"])
            )
        return True

    def add_webhook(self, name: str, kind: str, url: str, token: str = "") -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO webhooks (name, kind, url, token, enabled, created_at) "
                "VALUES (?, ?, ?, ?, 1, ?)",
                (name, kind, url, token, _now()),
            )
            return int(cur.lastrowid)

    def list_webhooks(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, name, kind, url, token, enabled, created_at FROM webhooks ORDER BY id DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def enabled_webhooks(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, name, kind, url, token FROM webhooks WHERE enabled=1"
            ).fetchall()
        return [dict(r) for r in rows]

    def toggle_webhook(self, webhook_id: int, enabled: bool) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE webhooks SET enabled=? WHERE id=?",
                (1 if enabled else 0, webhook_id),
            )

    def delete_webhook(self, webhook_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM webhooks WHERE id=?", (webhook_id,))

    def log_delivery(self, webhook_id: int, scan_id: int | None, status: str, detail: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO webhook_deliveries (webhook_id, scan_id, status, detail, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (webhook_id, scan_id, status, detail[:2000], _now()),
            )

    def recent_deliveries(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT d.id, d.webhook_id, w.name, d.scan_id, d.status, d.detail, d.created_at "
                "FROM webhook_deliveries d LEFT JOIN webhooks w ON w.id=d.webhook_id "
                "ORDER BY d.id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def add_watch(self, ioc: str, ioc_type: str, interval_hours: int) -> int:
        # Aynı değer zaten izleniyorsa aralığı güncelle, yeni satır açma
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO watchlist (ioc, ioc_type, interval_hours, enabled, created_at) "
                "VALUES (?, ?, ?, 1, ?) "
                "ON CONFLICT(ioc) DO UPDATE SET interval_hours=excluded.interval_hours, enabled=1",
                (ioc, ioc_type, interval_hours, _now()),
            )
            row = conn.execute("SELECT id FROM watchlist WHERE ioc=?", (ioc,)).fetchone()
        return int(row["id"])

    def list_watch(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM watchlist ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    def get_watch(self, watch_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM watchlist WHERE id=?", (watch_id,)).fetchone()
        return dict(row) if row else None

    def update_watch(self, watch_id: int, score: float, risk: str, checked_at: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE watchlist SET last_score=?, last_risk=?, last_checked=? WHERE id=?",
                (score, risk, checked_at, watch_id),
            )

    def delete_watch(self, watch_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM watchlist WHERE id=?", (watch_id,))
