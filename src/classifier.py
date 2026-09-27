"""Классификация трафика по правилам и машинному обучению."""

from __future__ import annotations

import random
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from src.models import PacketRecord

# Правила на основе портов и известных подсетей
PORT_RULES = {
  80: "Веб-трафик",
  443: "Веб-трафик",
  8080: "Веб-трафик",
  53: "DNS",
  19302: "Видеостриминг",
  3478: "Видеостриминг",
}

IP_PREFIX_RULES = {
  "142.250.": "Веб-трафик",      # Google
  "157.240.": "Социальные сети",  # Meta/Facebook
  "31.13.": "Социальные сети",
  "151.101.": "Видеостриминг",    # Twitch/CDN
  "104.16.": "Видеостриминг",     # Cloudflare video
  "13.107.": "Видеостриминг",     # Microsoft streaming
}

CATEGORIES = [
    "Веб-трафик",
    "Видеостриминг",
    "Социальные сети",
    "DNS",
    "Системный",
    "Прочее",
]


class TrafficClassifier:
    """Классификатор: правила + RandomForest."""

    def __init__(self, model_path: str, use_ml: bool = True) -> None:
        self.model_path = Path(model_path)
        self.use_ml = use_ml
        self._model: Optional[RandomForestClassifier] = None
        self._encoder: Optional[LabelEncoder] = None
        if use_ml:
            self._load_or_train()

    def classify(self, record: PacketRecord) -> str:
        rule_category = self._classify_by_rules(record)
        if self.use_ml and self._model and self._encoder:
            ml_category = self._classify_by_ml(record)
            if ml_category != "Прочее":
                return ml_category
        return rule_category

    def _classify_by_rules(self, record: PacketRecord) -> str:
        if record.protocol == "ICMP":
            return "Системный"

        for port in (record.dst_port, record.src_port):
            if port and port in PORT_RULES:
                return PORT_RULES[port]

        for prefix, category in IP_PREFIX_RULES.items():
            if record.dst_ip.startswith(prefix) or record.src_ip.startswith(prefix):
                return category

        if record.dst_port in (80, 443, 8080) or record.src_port in (80, 443, 8080):
            return "Веб-трафик"

        return "Прочее"

    def _features(self, record: PacketRecord) -> list:
        return [
            record.src_port or 0,
            record.dst_port or 0,
            {"TCP": 1, "UDP": 2, "ICMP": 3}.get(record.protocol, 0),
            record.size,
        ]

    def _classify_by_ml(self, record: PacketRecord) -> str:
        if not self._model or not self._encoder:
            return "Прочее"
        X = np.array([self._features(record)])
        pred = self._model.predict(X)[0]
        return self._encoder.inverse_transform([pred])[0]

    def _load_or_train(self) -> None:
        if self.model_path.exists():
            data = joblib.load(self.model_path)
            self._model = data["model"]
            self._encoder = data["encoder"]
            return
        self._train_and_save()

    def _train_and_save(self) -> None:
        """Обучение на синтетических данных, основанных на правилах."""
        X = []
        y = []
        random.seed(42)
        np.random.seed(42)

        profiles = [
            (443, 1, 800, "Веб-трафик"),
            (80, 1, 600, "Веб-трафик"),
            (53, 2, 100, "DNS"),
            (19302, 1, 5000, "Видеостриминг"),
            (3478, 2, 3000, "Видеостриминг"),
            (0, 3, 64, "Системный"),
            (random.randint(1024, 65535), 1, 400, "Прочее"),
        ]

        for _ in range(500):
            dst_port, proto_code, base_size, category = random.choice(profiles)
            src_port = random.randint(1024, 65535)
            size = base_size + random.randint(-100, 500)
            X.append([src_port, dst_port, proto_code, max(size, 64)])
            y.append(category)

        self._encoder = LabelEncoder()
        y_enc = self._encoder.fit_transform(y)
        self._model = RandomForestClassifier(n_estimators=50, random_state=42)
        self._model.fit(X, y_enc)

        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "encoder": self._encoder}, self.model_path)
