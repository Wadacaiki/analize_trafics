"""Тесты модулей анализа сетевого трафика."""

import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.analyzer import TrafficAnalyzer
from src.classifier import TrafficClassifier
from src.models import PacketRecord
from src.monitor import TrafficMonitor
from src.reporter import ReportGenerator
from src.storage import TrafficStorage


def _sample_record(**kwargs) -> PacketRecord:
    defaults = dict(
        timestamp=datetime.now(),
        src_ip="192.168.1.10",
        dst_ip="142.250.185.78",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        size=1200,
        category="Веб-трафик",
    )
    defaults.update(kwargs)
    return PacketRecord(**defaults)


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.storage = TrafficStorage(str(Path(self.tmp.name) / "test.db"))

    def tearDown(self):
        self.storage.close()
        self.tmp.cleanup()

    def test_save_and_query(self):
        record = _sample_record()
        self.storage.save_packet(record)
        results = self.storage.query_packets(protocol="TCP")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].dst_port, 443)


class TestClassifier(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        model_path = Path(self.tmp.name) / "model.joblib"
        self.classifier = TrafficClassifier(str(model_path), use_ml=True)

    def tearDown(self):
        self.storage.close()
        self.tmp.cleanup()

    def test_web_traffic_by_port(self):
        record = _sample_record(dst_port=443, protocol="TCP")
        self.assertEqual(self.classifier.classify(record), "Веб-трафик")

    def test_dns_by_port(self):
        record = _sample_record(dst_port=53, protocol="UDP", dst_ip="8.8.8.8")
        self.assertEqual(self.classifier.classify(record), "DNS")

    def test_icmp_system(self):
        record = _sample_record(protocol="ICMP", dst_port=None, src_port=None)
        self.assertEqual(self.classifier.classify(record), "Системный")


class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.storage = TrafficStorage(str(Path(self.tmp.name) / "test.db"))
        self.analyzer = TrafficAnalyzer(self.storage)
        self.storage.save_packets([
            _sample_record(protocol="TCP", size=1000, category="Веб-трафик"),
            _sample_record(protocol="UDP", dst_port=53, size=200, category="DNS"),
            _sample_record(protocol="ICMP", dst_port=None, size=64, category="Системный"),
        ])

    def tearDown(self):
        self.storage.close()
        self.tmp.cleanup()

    def test_filter_by_protocol(self):
        tcp_packets = self.analyzer.filter_packets(protocol="TCP")
        self.assertEqual(len(tcp_packets), 1)

    def test_stats(self):
        stats = self.analyzer.compute_stats()
        self.assertEqual(stats.total_packets, 3)
        self.assertEqual(stats.total_bytes, 1264)
        self.assertIn("TCP", stats.by_protocol)


class TestMonitor(unittest.TestCase):
    def test_threshold_alert(self):
        monitor = TrafficMonitor(bytes_per_minute=1000, connections_per_minute=2)
        alerts = []
        monitor.add_callback(lambda a: alerts.append(a))

        for i in range(5):
            monitor.process_packet(
                _sample_record(size=300, src_port=1000 + i, dst_port=443)
            )
        self.assertTrue(any(a.metric == "bytes_per_minute" for a in alerts))


class TestReporter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db_path = Path(self.tmp.name) / "test.db"
        out_dir = Path(self.tmp.name) / "reports"
        self.storage = TrafficStorage(str(db_path))
        self.analyzer = TrafficAnalyzer(self.storage)
        self.reporter = ReportGenerator(self.analyzer, str(out_dir))
        self.storage.save_packet(_sample_record())

    def tearDown(self):
        self.storage.close()
        self.tmp.cleanup()

    def test_csv_report(self):
        path = self.reporter.generate("csv")
        self.assertTrue(Path(path).exists())

    def test_html_report(self):
        path = self.reporter.generate("html")
        self.assertTrue(Path(path).exists())
        self.assertIn("html", path)

    def test_pdf_report(self):
        path = self.reporter.generate("pdf")
        self.assertTrue(Path(path).exists())


if __name__ == "__main__":
    unittest.main()
