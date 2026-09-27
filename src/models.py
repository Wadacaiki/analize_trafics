"""Модели данных для записей о сетевом трафике."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class PacketRecord:
    """Запись о захваченном пакете."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    size: int
    category: str = "Прочее"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "size": self.size,
            "category": self.category,
        }


@dataclass
class TrafficStats:
    """Агрегированная статистика трафика."""

    total_bytes: int = 0
    total_packets: int = 0
    connections: set = field(default_factory=set)
    by_protocol: dict = field(default_factory=dict)
    by_category: dict = field(default_factory=dict)
    by_src_ip: dict = field(default_factory=dict)
    by_dst_port: dict = field(default_factory=dict)

    @property
    def connection_count(self) -> int:
        return len(self.connections)

    def add_packet(self, record: PacketRecord) -> None:
        self.total_bytes += record.size
        self.total_packets += 1

        conn_key = (
            record.src_ip,
            record.dst_ip,
            record.src_port,
            record.dst_port,
            record.protocol,
        )
        self.connections.add(conn_key)

        self.by_protocol[record.protocol] = (
            self.by_protocol.get(record.protocol, 0) + record.size
        )
        self.by_category[record.category] = (
            self.by_category.get(record.category, 0) + record.size
        )
        self.by_src_ip[record.src_ip] = (
            self.by_src_ip.get(record.src_ip, 0) + record.size
        )
        if record.dst_port:
            self.by_dst_port[record.dst_port] = (
                self.by_dst_port.get(record.dst_port, 0) + record.size
            )
