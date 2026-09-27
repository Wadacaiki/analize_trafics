"""Уведомления по email и Telegram."""

from __future__ import annotations

import json
import smtplib
import urllib.error
import urllib.request
from email.mime.text import MIMEText
from typing import Optional

from src.monitor import Alert


class Notifier:
    """Отправка уведомлений о превышении порогов."""

    def __init__(self, config: dict) -> None:
        self.config = config

    def notify(self, alert: Alert) -> None:
        message = (
            f"[{alert.level.upper()}] {alert.message}\n"
            f"Метрика: {alert.metric}\n"
            f"Значение: {alert.value:.2f}\n"
            f"Порог: {alert.threshold:.2f}\n"
            f"Время: {alert.timestamp.isoformat()}"
        )
        if self.config.get("email_enabled"):
            self._send_email(f"Traffic Alert: {alert.metric}", message)
        if self.config.get("telegram_enabled"):
            self._send_telegram(message)

    def _send_email(self, subject: str, body: str) -> None:
        user = self.config.get("smtp_user", "")
        password = self.config.get("smtp_password", "")
        to_addr = self.config.get("email_to", "")
        if not all([user, password, to_addr]):
            return

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = user
        msg["To"] = to_addr

        try:
            with smtplib.SMTP(
                self.config.get("smtp_server", "smtp.gmail.com"),
                int(self.config.get("smtp_port", 587)),
            ) as server:
                server.starttls()
                server.login(user, password)
                server.sendmail(user, [to_addr], msg.as_string())
        except Exception:
            pass

    def _send_telegram(self, message: str) -> None:
        token = self.config.get("telegram_bot_token", "")
        chat_id = self.config.get("telegram_chat_id", "")
        if not token or not chat_id:
            return

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({"chat_id": chat_id, "text": message}).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        try:
            urllib.request.urlopen(req, timeout=10)
        except (urllib.error.URLError, TimeoutError):
            pass

    def test_notifications(self) -> tuple[bool, str]:
        """Проверка отправки email/Telegram (не влияет на журнал в программе)."""
        if not self.config.get("email_enabled") and not self.config.get("telegram_enabled"):
            return False, (
                "Email и Telegram отключены в config.json.\n"
                "Журнал предупреждений в программе работает отдельно — "
                "нажмите «Показать тестовое предупреждение» или снизьте пороги на вкладке Настройки."
            )

        alert = Alert(
            timestamp=__import__("datetime").datetime.now(),
            level="info",
            message="Тестовое уведомление системы анализа трафика",
            metric="test",
            value=0.0,
            threshold=0.0,
        )
        self.notify(alert)
        return True, "Тестовое уведомление отправлено (если настройки верны)"
