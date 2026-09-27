"""Анализ и фильтрация сетевого трафика."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from src.models import PacketRecord, TrafficStats
from src.storage import TrafficStorage


class TrafficAnalyzer:
    """Инструменты анализа и фильтрации трафика."""

    def __init__(self, storage: TrafficStorage) -> None:
        self.storage = storage

    def filter_packets(
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
        return self.storage.query_packets(
            start=start,
            end=end,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            category=category,
            limit=limit,
        )

    def compute_stats(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        **filters,
    ) -> TrafficStats:
        packets = self.filter_packets(start=start, end=end, **filters)
        stats = TrafficStats()
        for packet in packets:
            stats.add_packet(packet)
        return stats

    def top_talkers(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        top_n: int = 10,
    ) -> List[tuple]:
        stats = self.compute_stats(start=start, end=end)
        ranked = sorted(stats.by_src_ip.items(), key=lambda x: x[1], reverse=True)
        return ranked[:top_n]

    def top_ports(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        top_n: int = 10,
    ) -> List[tuple]:
        stats = self.compute_stats(start=start, end=end)
        ranked = sorted(stats.by_dst_port.items(), key=lambda x: x[1], reverse=True)
        return ranked[:top_n]

    def protocol_distribution(
        self, start: Optional[datetime] = None, end: Optional[datetime] = None
    ) -> dict:
        return self.storage.get_protocol_stats(start, end)

    def category_distribution(
        self, start: Optional[datetime] = None, end: Optional[datetime] = None
    ) -> dict:
        return self.storage.get_category_stats(start, end)

    def bytes_per_minute(
        self, start: Optional[datetime] = None, end: Optional[datetime] = None
    ) -> dict:
        packets = self.filter_packets(start=start, end=end)
        buckets: dict[str, int] = {}
        for packet in packets:
            key = packet.timestamp.strftime("%Y-%m-%d %H:%M")
            buckets[key] = buckets.get(key, 0) + packet.size
        return dict(sorted(buckets.items()))
