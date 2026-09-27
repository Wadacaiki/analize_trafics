"""Сервисный слой: связывает все модули приложения."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional

from src.analyzer import TrafficAnalyzer
from src.classifier import TrafficClassifier
from src.models import PacketRecord, TrafficStats
from src.monitor import Alert, TrafficMonitor
from src.notifier import Notifier
from src.packet_capture import PacketCapture
from src.reporter import ReportGenerator
from src.storage import TrafficStorage


class TrafficAnalysisApp:
    """Главный класс приложения анализа трафика."""

    def __init__(self, config_path: str = "config/config.json") -> None:
        self.config_path = Path(config_path)
        self.config = self._load_config()

        storage_cfg = self.config.get("storage", {})
        self.storage = TrafficStorage(storage_cfg.get("db_path", "data/traffic.db"))
        self.analyzer = TrafficAnalyzer(self.storage)
        self.reporter = ReportGenerator(self.analyzer)

        cls_cfg = self.config.get("classification", {})
        self.classifier = TrafficClassifier(
            model_path=cls_cfg.get("model_path", "data/traffic_model.joblib"),
            use_ml=cls_cfg.get("use_ml", True),
        )

        thr = self.config.get("thresholds", {})
        self.monitor = TrafficMonitor(
            bytes_per_minute=thr.get("bytes_per_minute", 10 * 1024 * 1024),
            connections_per_minute=thr.get("connections_per_minute", 500),
            anomaly_z_score=thr.get("anomaly_z_score", 2.5),
        )

        self.notifier = Notifier(self.config.get("notifications", {}))
        self.monitor.add_callback(self.notifier.notify)

        cap_cfg = self.config.get("capture", {})
        self.capture = PacketCapture(
            interface=cap_cfg.get("interface"),
            bpf_filter=cap_cfg.get("bpf_filter", ""),
            demo_mode=cap_cfg.get("demo_mode", True),
        )
        self.capture.add_callback(self._on_packet)

        self._live_callbacks: List[Callable[[PacketRecord], None]] = []
        self._alert_callbacks: List[Callable[[Alert], None]] = []
        self._stats_callbacks: List[Callable[[TrafficStats], None]] = []
        self.monitor.add_callback(self._on_alert)

        self._session_stats = TrafficStats()

    def _load_config(self) -> dict:
        if self.config_path.exists():
            with open(self.config_path, encoding="utf-8") as f:
                return json.load(f)
        return {}

    def save_config(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self.config, f, ensure_ascii=False, indent=2)

    def on_packet(self, callback: Callable[[PacketRecord], None]) -> None:
        self._live_callbacks.append(callback)

    def on_alert(self, callback: Callable[[Alert], None]) -> None:
        self._alert_callbacks.append(callback)

    def on_stats(self, callback: Callable[[TrafficStats], None]) -> None:
        self._stats_callbacks.append(callback)

    def _on_packet(self, record: PacketRecord) -> None:
        record.category = self.classifier.classify(record)
        self.storage.save_packet(record)
        self._session_stats.add_packet(record)
        self.monitor.process_packet(record)

        for cb in self._live_callbacks:
            try:
                cb(record)
            except Exception:
                pass
        for cb in self._stats_callbacks:
            try:
                cb(self._session_stats)
            except Exception:
                pass

    def _on_alert(self, alert: Alert) -> None:
        for cb in self._alert_callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def start_capture(self) -> None:
        self.capture.start()

    def stop_capture(self) -> None:
        self.capture.stop()

    def is_capturing(self) -> bool:
        return self.capture._running

    def reset_session_stats(self) -> None:
        self._session_stats = TrafficStats()

    def get_session_stats(self) -> TrafficStats:
        return self._session_stats

    def generate_report(
        self,
        fmt: str,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        category: Optional[str] = None,
    ) -> str:
        return self.reporter.generate(fmt, start, end, category)

    def update_thresholds(self, **kwargs) -> None:
        if "bytes_per_minute" in kwargs:
            self.monitor.bytes_per_minute = int(kwargs["bytes_per_minute"])
        if "connections_per_minute" in kwargs:
            self.monitor.connections_per_minute = int(kwargs["connections_per_minute"])
        if "anomaly_z_score" in kwargs:
            self.monitor.anomaly_z_score = float(kwargs["anomaly_z_score"])
        self.config.setdefault("thresholds", {}).update(kwargs)
        self.save_config()

    def set_demo_mode(self, enabled: bool) -> None:
        was_running = self.is_capturing()
        if was_running:
            self.stop_capture()
        self.capture.demo_mode = enabled
        self.config.setdefault("capture", {})["demo_mode"] = enabled
        self.save_config()
        if was_running:
            self.start_capture()

    def list_interfaces(self) -> list[str]:
        return PacketCapture.list_interfaces()

    def test_notifications(self) -> tuple[bool, str]:
        return self.notifier.test_notifications()

    def emit_demo_alert(self) -> Alert:
        """Тестовое предупреждение для демонстрации (журнал в GUI)."""
        alert = Alert(
            timestamp=datetime.now(),
            level="warning",
            message="Тестовое предупреждение: превышен порог расхода трафика",
            metric="bytes_per_minute",
            value=15000.0,
            threshold=float(self.monitor.bytes_per_minute),
        )
        self._on_alert(alert)
        self.notifier.notify(alert)
        return alert
