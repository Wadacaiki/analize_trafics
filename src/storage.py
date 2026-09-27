"""Хранение данных о трафике в SQLite."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional

from src.models import PacketRecord


class TrafficStorage:
    """Персистентное хранилище записей о пакетах."""

    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def _connect(self) -> sqlite3.Connection:
        return self._conn

    def _init_db(self) -> None:
        conn = self._connect()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                size INTEGER NOT NULL,
                category TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_packets_category ON packets(category)"
        )
        conn.commit()

    def save_packet(self, record: PacketRecord) -> None:
        conn = self._connect()
        conn.execute(
                """
                INSERT INTO packets
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size, category)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.timestamp.isoformat(),
                    record.src_ip,
                    record.dst_ip,
                    record.src_port,
                    record.dst_port,
                    record.protocol,
                    record.size,
                    record.category,
                ),
        )
        conn.commit()

    def save_packets(self, records: Iterable[PacketRecord]) -> None:
        rows = [
            (
                r.timestamp.isoformat(),
                r.src_ip,
                r.dst_ip,
                r.src_port,
                r.dst_port,
                r.protocol,
                r.size,
                r.category,
            )
            for r in records
        ]
        if not rows:
            return
        conn = self._connect()
        conn.executemany(
            """
            INSERT INTO packets
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size, category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()

    def query_packets(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        protocol: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        category: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[PacketRecord]:
        clauses = []
        params: list = []

        if start:
            clauses.append("timestamp >= ?")
            params.append(start.isoformat())
        if end:
            clauses.append("timestamp <= ?")
            params.append(end.isoformat())
        if protocol:
            clauses.append("protocol = ?")
            params.append(protocol.upper())
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if dst_ip:
            clauses.append("dst_ip = ?")
            params.append(dst_ip)
        if dst_port is not None:
            clauses.append("dst_port = ?")
            params.append(dst_port)
        if category:
            clauses.append("category = ?")
            params.append(category)

        sql = "SELECT * FROM packets"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY timestamp DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"

        rows = self._connect().execute(sql, params).fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_category_stats(
        self, start: Optional[datetime] = None, end: Optional[datetime] = None
    ) -> dict:
        clauses = []
        params: list = []
        if start:
            clauses.append("timestamp >= ?")
            params.append(start.isoformat())
        if end:
            clauses.append("timestamp <= ?")
            params.append(end.isoformat())

        sql = "SELECT category, SUM(size) as total FROM packets"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " GROUP BY category ORDER BY total DESC"

        rows = self._connect().execute(sql, params).fetchall()
        return {row["category"]: row["total"] for row in rows}

    def get_protocol_stats(
        self, start: Optional[datetime] = None, end: Optional[datetime] = None
    ) -> dict:
        clauses = []
        params: list = []
        if start:
            clauses.append("timestamp >= ?")
            params.append(start.isoformat())
        if end:
            clauses.append("timestamp <= ?")
            params.append(end.isoformat())

        sql = "SELECT protocol, SUM(size) as total FROM packets"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " GROUP BY protocol ORDER BY total DESC"

        rows = self._connect().execute(sql, params).fetchall()
        return {row["protocol"]: row["total"] for row in rows}

    def clear(self) -> None:
        conn = self._connect()
        conn.execute("DELETE FROM packets")
        conn.commit()

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> PacketRecord:
        return PacketRecord(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            protocol=row["protocol"],
            size=row["size"],
            category=row["category"],
        )

    def export_json(self, path: str, records: List[PacketRecord]) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump([r.to_dict() for r in records], f, ensure_ascii=False, indent=2)
