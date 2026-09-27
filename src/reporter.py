"""Генерация отчётов в PDF, HTML и CSV."""

from __future__ import annotations

import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from src.analyzer import TrafficAnalyzer
from src.models import TrafficStats

_CYRILLIC_FONT = None


def _find_cyrillic_font() -> Optional[str]:
    """Регистрирует TTF-шрифт с поддержкой кириллицы для ReportLab."""
    global _CYRILLIC_FONT
    if _CYRILLIC_FONT:
        return _CYRILLIC_FONT

    candidates = [
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts" / "arial.ttf",
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts" / "calibri.ttf",
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/TTF/DejaVuSans.ttf"),
    ]
    for font_path in candidates:
        if font_path.exists():
            pdfmetrics.registerFont(TTFont("ReportCyr", str(font_path)))
            _CYRILLIC_FONT = "ReportCyr"
            return _CYRILLIC_FONT
    return None


def _setup_chart_fonts() -> None:
    plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "Arial", "Calibri"]
    plt.rcParams["axes.unicode_minus"] = False


def _pdf_styles():
    font = _find_cyrillic_font()
    base = getSampleStyleSheet()
    if not font:
        return base["Title"], base["Normal"]

    title = ParagraphStyle(
        "CyrTitle",
        parent=base["Title"],
        fontName=font,
        fontSize=18,
    )
    normal = ParagraphStyle(
        "CyrNormal",
        parent=base["Normal"],
        fontName=font,
        fontSize=11,
    )
    return title, normal


class ReportGenerator:
    """Формирование отчётов с графиками."""

    def __init__(self, analyzer: TrafficAnalyzer, output_dir: str = "reports") -> None:
        self.analyzer = analyzer
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        fmt: str,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        category: Optional[str] = None,
    ) -> str:
        fmt = fmt.lower()
        if fmt == "csv":
            return self._generate_csv(start, end, category)
        if fmt == "html":
            return self._generate_html(start, end, category)
        if fmt == "pdf":
            return self._generate_pdf(start, end, category)
        raise ValueError(f"Неподдерживаемый формат: {fmt}")

    def _collect_data(
        self,
        start: Optional[datetime],
        end: Optional[datetime],
        category: Optional[str],
    ) -> tuple[TrafficStats, dict, dict, dict]:
        stats = self.analyzer.compute_stats(
            start=start, end=end, category=category
        )
        by_category = self.analyzer.category_distribution(start, end)
        by_protocol = self.analyzer.protocol_distribution(start, end)
        by_minute = self.analyzer.bytes_per_minute(start, end)
        return stats, by_category, by_protocol, by_minute

    def _chart_paths(
        self, by_category: dict, by_protocol: dict, prefix: str
    ) -> tuple[str, str]:
        _setup_chart_fonts()
        pie_path = str(self.output_dir / f"{prefix}_pie.png")
        bar_path = str(self.output_dir / f"{prefix}_bar.png")

        if by_category:
            plt.figure(figsize=(6, 4))
            plt.pie(
                list(by_category.values()),
                labels=list(by_category.keys()),
                autopct="%1.1f%%",
            )
            plt.title("Распределение по категориям")
            plt.tight_layout()
            plt.savefig(pie_path, dpi=120)
            plt.close()

        if by_protocol:
            plt.figure(figsize=(6, 4))
            plt.bar(list(by_protocol.keys()), list(by_protocol.values()))
            plt.title("Объём по протоколам")
            plt.ylabel("Байты")
            plt.tight_layout()
            plt.savefig(bar_path, dpi=120)
            plt.close()

        return pie_path, bar_path

    def _generate_csv(
        self,
        start: Optional[datetime],
        end: Optional[datetime],
        category: Optional[str],
    ) -> str:
        packets = self.analyzer.filter_packets(start=start, end=end, category=category)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.output_dir / f"report_{ts}.csv"

        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "timestamp",
                    "src_ip",
                    "dst_ip",
                    "src_port",
                    "dst_port",
                    "protocol",
                    "size",
                    "category",
                ],
            )
            writer.writeheader()
            for p in packets:
                writer.writerow(p.to_dict())

        return str(path)

    def _generate_html(
        self,
        start: Optional[datetime],
        end: Optional[datetime],
        category: Optional[str],
    ) -> str:
        stats, by_category, by_protocol, by_minute = self._collect_data(
            start, end, category
        )
        prefix = datetime.now().strftime("%Y%m%d_%H%M%S")
        pie_path, bar_path = self._chart_paths(by_category, by_protocol, prefix)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.output_dir / f"report_{ts}.html"

        period = self._period_str(start, end)
        cat_filter = category or "Все"

        rows_cat = "".join(
            f"<tr><td>{k}</td><td>{self._fmt_bytes(v)}</td></tr>"
            for k, v in by_category.items()
        )
        rows_proto = "".join(
            f"<tr><td>{k}</td><td>{self._fmt_bytes(v)}</td></tr>"
            for k, v in by_protocol.items()
        )

        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>Отчёт по сетевому трафику</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    h1, h2 {{ color: #1a365d; }}
    table {{ border-collapse: collapse; width: 60%; margin-bottom: 20px; }}
    th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
    th {{ background: #edf2f7; }}
    .charts img {{ max-width: 480px; margin-right: 16px; }}
  </style>
</head>
<body>
  <h1>Отчёт по анализу сетевого трафика</h1>
  <p><b>Период:</b> {period}</p>
  <p><b>Категория:</b> {cat_filter}</p>
  <p><b>Всего пакетов:</b> {stats.total_packets}</p>
  <p><b>Объём данных:</b> {self._fmt_bytes(stats.total_bytes)}</p>
  <p><b>Подключений:</b> {stats.connection_count}</p>

  <div class="charts">
    <img src="{Path(pie_path).name}" alt="Категории">
    <img src="{Path(bar_path).name}" alt="Протоколы">
  </div>

  <h2>По категориям</h2>
  <table><tr><th>Категория</th><th>Объём</th></tr>{rows_cat}</table>

  <h2>По протоколам</h2>
  <table><tr><th>Протокол</th><th>Объём</th></tr>{rows_proto}</table>

  <p><i>Сформировано: {datetime.now().strftime("%d.%m.%Y %H:%M:%S")}</i></p>
</body>
</html>"""
        path.write_text(html, encoding="utf-8")
        return str(path)

    def _generate_pdf(
        self,
        start: Optional[datetime],
        end: Optional[datetime],
        category: Optional[str],
    ) -> str:
        stats, by_category, by_protocol, _ = self._collect_data(start, end, category)
        prefix = datetime.now().strftime("%Y%m%d_%H%M%S")
        pie_path, bar_path = self._chart_paths(by_category, by_protocol, prefix)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.output_dir / f"report_{ts}.pdf"

        doc = SimpleDocTemplate(str(path), pagesize=A4)
        title_style, normal_style = _pdf_styles()
        font = _find_cyrillic_font()
        story = []

        story.append(Paragraph("Отчёт по анализу сетевого трафика", title_style))
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph(f"Период: {self._period_str(start, end)}", normal_style))
        story.append(Paragraph(f"Категория: {category or 'Все'}", normal_style))
        story.append(Paragraph(f"Пакетов: {stats.total_packets}", normal_style))
        story.append(
            Paragraph(f"Объём: {self._fmt_bytes(stats.total_bytes)}", normal_style)
        )
        story.append(
            Paragraph(f"Подключений: {stats.connection_count}", normal_style)
        )
        story.append(Spacer(1, 0.5 * cm))

        if by_category:
            data = [
                [
                    Paragraph("Категория", normal_style),
                    Paragraph("Объём (байт)", normal_style),
                ]
            ] + [
                [Paragraph(str(k), normal_style), Paragraph(str(v), normal_style)]
                for k, v in by_category.items()
            ]
            table = Table(data, colWidths=[8 * cm, 6 * cm])
            style_cmds = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
            if font:
                style_cmds.append(("FONTNAME", (0, 0), (-1, -1), font))
            table.setStyle(TableStyle(style_cmds))
            story.append(table)
            story.append(Spacer(1, 0.5 * cm))

        if Path(pie_path).exists():
            story.append(Image(pie_path, width=14 * cm, height=9 * cm))
        if Path(bar_path).exists():
            story.append(Spacer(1, 0.3 * cm))
            story.append(Image(bar_path, width=14 * cm, height=9 * cm))

        doc.build(story)
        return str(path)

    @staticmethod
    def _period_str(start: Optional[datetime], end: Optional[datetime]) -> str:
        if start and end:
            return f"{start.strftime('%d.%m.%Y %H:%M')} — {end.strftime('%d.%m.%Y %H:%M')}"
        if start:
            return f"с {start.strftime('%d.%m.%Y %H:%M')}"
        if end:
            return f"до {end.strftime('%d.%m.%Y %H:%M')}"
        return "Весь доступный период"

    @staticmethod
    def _fmt_bytes(value: int) -> str:
        if value < 1024:
            return f"{value} B"
        if value < 1024 ** 2:
            return f"{value / 1024:.1f} KB"
        return f"{value / 1024 ** 2:.2f} MB"
