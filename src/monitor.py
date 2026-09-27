"""Мониторинг аномалий и пороговых значений."""

from __future__ import annotations

import statistics
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Deque, List, Optional

from src.models import PacketRecord


@dataclass
class Alert:
    """Уведомление о превышении порога или аномалии."""

    timestamp: datetime
    level: str
    message: str
    metric: str
    value: float
    threshold: float


AlertCallback = Callable[[Alert], None]


@dataclass
class MonitorState:
    """Состояние монитора за текущую минуту."""

    minute_key: str = ""
    bytes_count: int = 0
    packet_count: int = 0
    connections: set = field(default_factory=set)


class TrafficMonitor:
    """Отслеживание порогов и статистических аномалий."""

    def __init__(
        self,
        bytes_per_minute: int = 10 * 1024 * 1024,
        connections_per_minute: int = 500,
        anomaly_z_score: float = 2.5,
        history_size: int = 30,
    ) -> None:
        self.bytes_per_minute = bytes_per_minute
        self.connections_per_minute = connections_per_minute
        self.anomaly_z_score = anomaly_z_score
        self.history_size = history_size

        self._current = MonitorState()
        self._minute_history: Deque[int] = deque(maxlen=history_size)
        self._alerts: List[Alert] = []
        self._callbacks: List[AlertCallback] = []

    def add_callback(self, callback: AlertCallback) -> None:
        self._callbacks.append(callback)

    def process_packet(self, record: PacketRecord) -> List[Alert]:
        alerts: List[Alert] = []
        minute_key = record.timestamp.strftime("%Y-%m-%d %H:%M")

        if self._current.minute_key != minute_key:
            if self._current.minute_key:
                self._minute_history.append(self._current.bytes_count)
                alerts.extend(self._check_minute(self._current))
            self._current = MonitorState(minute_key=minute_key)

        self._current.bytes_count += record.size
        self._current.packet_count += 1
        self._current.connections.add(
            (record.src_ip, record.dst_ip, record.src_port, record.dst_port)
        )

        if self._current.bytes_count > self.bytes_per_minute:
            alerts.append(
                self._make_alert(
                    "warning",
                    f"Превышен порог трафика: {self._format_bytes(self._current.bytes_count)}",
                    "bytes_per_minute",
                    float(self._current.bytes_count),
                    float(self.bytes_per_minute),
                )
            )

        if len(self._current.connections) > self.connections_per_minute:
            alerts.append(
                self._make_alert(
                    "warning",
                    f"Превышен порог подключений: {len(self._current.connections)}",
                    "connections_per_minute",
                    float(len(self._current.connections)),
                    float(self.connections_per_minute),
                )
            )

        for alert in alerts:
            self._emit(alert)
        return alerts

    def _check_minute(self, state: MonitorState) -> List[Alert]:
        alerts: List[Alert] = []
        if len(self._minute_history) < 5:
            return alerts

        mean = statistics.mean(self._minute_history)
        stdev = statistics.stdev(self._minute_history) or 1.0
        z = (state.bytes_count - mean) / stdev

        if z > self.anomaly_z_score:
            alerts.append(
                self._make_alert(
                    "critical",
                    f"Аномалия трафика: Z-score={z:.2f}, объём={self._format_bytes(state.bytes_count)}",
                    "anomaly_z_score",
                    z,
                    self.anomaly_z_score,
                )
            )
            self._emit(alerts[-1])
        return alerts

    def _make_alert(
        self, level: str, message: str, metric: str, value: float, threshold: float
    ) -> Alert:
        alert = Alert(
            timestamp=datetime.now(),
            level=level,
            message=message,
            metric=metric,
            value=value,
            threshold=threshold,
        )
        self._alerts.append(alert)
        if len(self._alerts) > 200:
            self._alerts = self._alerts[-200:]
        return alert

    def _emit(self, alert: Alert) -> None:
        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def get_recent_alerts(self, minutes: int = 60) -> List[Alert]:
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return [a for a in self._alerts if a.timestamp >= cutoff]

    @staticmethod
    def _format_bytes(value: int) -> str:
        if value < 1024:
            return f"{value} B"
        if value < 1024 ** 2:
            return f"{value / 1024:.1f} KB"
        return f"{value / 1024 ** 2:.2f} MB"
