"""Захват сетевых пакетов (libpcap/Npcap через Scapy)."""

from __future__ import annotations

import random
import threading
import time
from datetime import datetime
from typing import Callable, Optional

from src.models import PacketRecord

try:
    from scapy.all import ICMP, IP, TCP, UDP, sniff
    from scapy.config import conf

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


PacketCallback = Callable[[PacketRecord], None]


class PacketCapture:
    """Захват пакетов в реальном времени или демо-режим."""

    DEMO_PROFILES = [
        ("192.168.1.10", "142.250.185.78", 54321, 443, "TCP", 1200, "Веб-трафик"),
        ("192.168.1.10", "157.240.241.35", 54322, 443, "TCP", 2500, "Социальные сети"),
        ("192.168.1.10", "151.101.193.140", 54323, 443, "TCP", 8000, "Видеостриминг"),
        ("192.168.1.10", "8.8.8.8", 54324, 53, "UDP", 120, "DNS"),
        ("192.168.1.10", "1.1.1.1", 0, 0, "ICMP", 64, "Системный"),
        ("192.168.1.15", "142.250.185.78", 49152, 80, "TCP", 900, "Веб-трафик"),
        ("192.168.1.15", "104.16.132.229", 49153, 443, "TCP", 15000, "Видеостриминг"),
    ]

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "",
        demo_mode: bool = False,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.demo_mode = demo_mode or not SCAPY_AVAILABLE
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: list[PacketCallback] = []

    def add_callback(self, callback: PacketCallback) -> None:
        self._callbacks.append(callback)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        if self.demo_mode:
            self._thread = threading.Thread(target=self._demo_loop, daemon=True)
        else:
            self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def _notify(self, record: PacketRecord) -> None:
        for cb in self._callbacks:
            try:
                cb(record)
            except Exception:
                pass

    def _demo_loop(self) -> None:
        while self._running:
            src_ip, dst_ip, src_port, dst_port, proto, size, _ = random.choice(
                self.DEMO_PROFILES
            )
            size = size + random.randint(-200, 500)
            record = PacketRecord(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port if src_port else None,
                dst_port=dst_port if dst_port else None,
                protocol=proto,
                size=max(size, 64),
            )
            self._notify(record)
            time.sleep(random.uniform(0.05, 0.3))

    def _capture_loop(self) -> None:
        if not SCAPY_AVAILABLE:
            self._demo_loop()
            return

        def _handler(packet) -> None:
            record = self._parse_packet(packet)
            if record:
                self._notify(record)

        kwargs = {
            "prn": _handler,
            "store": False,
            "stop_filter": lambda _: not self._running,
        }
        if self.interface:
            kwargs["iface"] = self.interface
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter

        try:
            sniff(**kwargs)
        except Exception:
            self.demo_mode = True
            self._demo_loop()

    @staticmethod
    def _parse_packet(packet) -> Optional[PacketRecord]:
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "OTHER"
        src_port = None
        dst_port = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        return PacketRecord(
            timestamp=datetime.now(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            size=len(packet),
        )

    @staticmethod
    def list_interfaces() -> list[str]:
        if not SCAPY_AVAILABLE:
            return ["demo"]
        try:
            return list(conf.ifaces.keys())
        except Exception:
            return ["demo"]
