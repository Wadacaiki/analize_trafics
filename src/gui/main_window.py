"""Графический интерфейс приложения анализа трафика."""

from __future__ import annotations

import tkinter as tk
from datetime import datetime, timedelta
from tkinter import filedialog, messagebox, ttk

from src.app import TrafficAnalysisApp
from src.classifier import CATEGORIES
from src.models import PacketRecord


class TrafficAnalyzerGUI:
    """Главное окно с вкладками мониторинга, анализа и отчётов."""

    def __init__(self, app: TrafficAnalysisApp) -> None:
        self.app = app
        self.root = tk.Tk()
        self.root.title("Анализ сетевого трафика")
        self.root.geometry("1100x700")
        self.root.minsize(900, 600)

        self._build_menu()
        self._build_notebook()
        self._bind_app_events()

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Сбросить статистику сессии", command=self._reset_stats)
        file_menu.add_command(label="Очистить базу данных", command=self._clear_db)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.root.quit)
        menubar.add_cascade(label="Файл", menu=file_menu)
        self.root.config(menu=menubar)

    def _build_notebook(self) -> None:
        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.tab_monitor = ttk.Frame(nb)
        self.tab_analysis = ttk.Frame(nb)
        self.tab_reports = ttk.Frame(nb)
        self.tab_alerts = ttk.Frame(nb)
        self.tab_settings = ttk.Frame(nb)

        nb.add(self.tab_monitor, text="Мониторинг")
        nb.add(self.tab_analysis, text="Анализ")
        nb.add(self.tab_reports, text="Отчёты")
        nb.add(self.tab_alerts, text="Уведомления")
        nb.add(self.tab_settings, text="Настройки")

        self._build_monitor_tab()
        self._build_analysis_tab()
        self._build_reports_tab()
        self._build_alerts_tab()
        self._build_settings_tab()

    def _build_monitor_tab(self) -> None:
        ctrl = ttk.LabelFrame(self.tab_monitor, text="Управление захватом")
        ctrl.pack(fill=tk.X, padx=8, pady=8)

        self.demo_var = tk.BooleanVar(value=self.app.config.get("capture", {}).get("demo_mode", True))
        ttk.Checkbutton(
            ctrl, text="Демо-режим (без прав администратора)", variable=self.demo_var,
            command=self._toggle_demo,
        ).grid(row=0, column=0, padx=4, pady=4, sticky="w")

        ttk.Label(ctrl, text="Интерфейс:").grid(row=0, column=1, padx=4)
        self.iface_var = tk.StringVar()
        iface_combo = ttk.Combobox(ctrl, textvariable=self.iface_var, width=30, state="readonly")
        iface_combo["values"] = self.app.list_interfaces()
        if iface_combo["values"]:
            iface_combo.current(0)
        iface_combo.grid(row=0, column=2, padx=4)

        ttk.Label(ctrl, text="BPF-фильтр:").grid(row=1, column=0, padx=4, sticky="w")
        self.bpf_var = tk.StringVar(value=self.app.config.get("capture", {}).get("bpf_filter", ""))
        ttk.Entry(ctrl, textvariable=self.bpf_var, width=50).grid(row=1, column=1, columnspan=2, padx=4, pady=4, sticky="w")

        btn_frame = ttk.Frame(ctrl)
        btn_frame.grid(row=2, column=0, columnspan=3, pady=6)
        self.btn_start = ttk.Button(btn_frame, text="▶ Старт", command=self._start_capture)
        self.btn_stop = ttk.Button(btn_frame, text="■ Стоп", command=self._stop_capture, state=tk.DISABLED)
        self.btn_start.pack(side=tk.LEFT, padx=4)
        self.btn_stop.pack(side=tk.LEFT, padx=4)

        stats_frame = ttk.LabelFrame(self.tab_monitor, text="Статистика сессии")
        stats_frame.pack(fill=tk.X, padx=8, pady=4)
        self.lbl_packets = ttk.Label(stats_frame, text="Пакетов: 0")
        self.lbl_bytes = ttk.Label(stats_frame, text="Объём: 0 B")
        self.lbl_connections = ttk.Label(stats_frame, text="Подключений: 0")
        self.lbl_packets.pack(side=tk.LEFT, padx=12, pady=4)
        self.lbl_bytes.pack(side=tk.LEFT, padx=12, pady=4)
        self.lbl_connections.pack(side=tk.LEFT, padx=12, pady=4)

        table_frame = ttk.LabelFrame(self.tab_monitor, text="Пакеты в реальном времени")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        cols = ("time", "src", "dst", "sport", "dport", "proto", "size", "category")
        self.packet_tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=18)
        headers = {
            "time": "Время", "src": "Источник", "dst": "Назначение",
            "sport": "Порт src", "dport": "Порт dst", "proto": "Протокол",
            "size": "Размер", "category": "Категория",
        }
        for col, title in headers.items():
            self.packet_tree.heading(col, text=title)
            self.packet_tree.column(col, width=100 if col != "category" else 130)

        scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=scroll.set)
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_analysis_tab(self) -> None:
        filt = ttk.LabelFrame(self.tab_analysis, text="Фильтры")
        filt.pack(fill=tk.X, padx=8, pady=8)

        self.f_proto = tk.StringVar()
        self.f_src = tk.StringVar()
        self.f_dst = tk.StringVar()
        self.f_port = tk.StringVar()
        self.f_category = tk.StringVar()

        fields = [
            ("Протокол (TCP/UDP/ICMP):", self.f_proto),
            ("IP источника:", self.f_src),
            ("IP назначения:", self.f_dst),
            ("Порт назначения:", self.f_port),
            ("Категория:", self.f_category),
        ]
        for i, (label, var) in enumerate(fields):
            ttk.Label(filt, text=label).grid(row=i // 2, column=(i % 2) * 2, padx=4, pady=4, sticky="e")
            if label.startswith("Категория"):
                cb = ttk.Combobox(filt, textvariable=var, values=[""] + CATEGORIES, width=22)
            else:
                cb = ttk.Entry(filt, textvariable=var, width=24)
            cb.grid(row=i // 2, column=(i % 2) * 2 + 1, padx=4, pady=4)

        ttk.Button(filt, text="Применить фильтр", command=self._apply_filter).grid(
            row=3, column=0, columnspan=4, pady=8
        )

        result = ttk.LabelFrame(self.tab_analysis, text="Результаты анализа")
        result.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.analysis_text = tk.Text(result, height=20, wrap=tk.WORD)
        self.analysis_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    def _build_reports_tab(self) -> None:
        frame = ttk.LabelFrame(self.tab_reports, text="Параметры отчёта")
        frame.pack(fill=tk.X, padx=8, pady=8)

        self.report_period = tk.StringVar(value="1")
        self.report_category = tk.StringVar(value="")
        self.report_format = tk.StringVar(value="html")

        ttk.Label(frame, text="Период (часов назад):").grid(row=0, column=0, padx=4, pady=4)
        ttk.Spinbox(frame, from_=1, to=168, textvariable=self.report_period, width=8).grid(row=0, column=1, padx=4)
        ttk.Label(frame, text="Категория:").grid(row=0, column=2, padx=4)
        ttk.Combobox(
            frame, textvariable=self.report_category,
            values=[""] + CATEGORIES, width=20,
        ).grid(row=0, column=3, padx=4)

        ttk.Label(frame, text="Формат:").grid(row=1, column=0, padx=4, pady=4)
        ttk.Combobox(
            frame, textvariable=self.report_format,
            values=["html", "pdf", "csv"], width=10, state="readonly",
        ).grid(row=1, column=1, padx=4)

        ttk.Button(frame, text="Сформировать отчёт", command=self._generate_report).grid(
            row=1, column=2, columnspan=2, padx=4, pady=8
        )

        self.report_status = ttk.Label(self.tab_reports, text="Отчёт ещё не создан")
        self.report_status.pack(anchor="w", padx=12, pady=4)

    def _build_alerts_tab(self) -> None:
        hint = ttk.Label(
            self.tab_alerts,
            text=(
                "Журнал заполняется автоматически при превышении порогов (вкладка «Настройки»).\n"
                "Email и Telegram — опционально, настраиваются в config/config.json."
            ),
            justify=tk.LEFT,
        )
        hint.pack(anchor="w", padx=12, pady=(8, 0))

        frame = ttk.LabelFrame(self.tab_alerts, text="Журнал предупреждений")
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        cols = ("time", "level", "message")
        self.alert_tree = ttk.Treeview(frame, columns=cols, show="headings", height=20)
        for col, title, w in [("time", "Время", 150), ("level", "Уровень", 80), ("message", "Сообщение", 600)]:
            self.alert_tree.heading(col, text=title)
            self.alert_tree.column(col, width=w)
        self.alert_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        btn_frame = ttk.Frame(self.tab_alerts)
        btn_frame.pack(pady=4)
        ttk.Button(
            btn_frame, text="Показать тестовое предупреждение", command=self._show_demo_alert
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(
            btn_frame, text="Тест email/Telegram", command=self._test_notify
        ).pack(side=tk.LEFT, padx=4)

    def _build_settings_tab(self) -> None:
        frame = ttk.LabelFrame(self.tab_settings, text="Пороговые значения")
        frame.pack(fill=tk.X, padx=8, pady=8)

        thr = self.app.config.get("thresholds", {})
        self.thr_bytes = tk.StringVar(value=str(thr.get("bytes_per_minute", 10485760)))
        self.thr_conn = tk.StringVar(value=str(thr.get("connections_per_minute", 500)))
        self.thr_z = tk.StringVar(value=str(thr.get("anomaly_z_score", 2.5)))

        ttk.Label(frame, text="Байт в минуту:").grid(row=0, column=0, padx=4, pady=4, sticky="e")
        ttk.Entry(frame, textvariable=self.thr_bytes, width=20).grid(row=0, column=1, padx=4)
        ttk.Label(frame, text="Подключений в минуту:").grid(row=1, column=0, padx=4, pady=4, sticky="e")
        ttk.Entry(frame, textvariable=self.thr_conn, width=20).grid(row=1, column=1, padx=4)
        ttk.Label(frame, text="Z-score аномалии:").grid(row=2, column=0, padx=4, pady=4, sticky="e")
        ttk.Entry(frame, textvariable=self.thr_z, width=20).grid(row=2, column=1, padx=4)
        ttk.Button(frame, text="Сохранить пороги", command=self._save_thresholds).grid(
            row=3, column=0, columnspan=2, pady=8
        )

        info = ttk.Label(
            self.tab_settings,
            text=(
                "Для реального захвата пакетов установите Npcap (Windows) и запустите\n"
                "программу от имени администратора. Отключите демо-режим на вкладке Мониторинг.\n\n"
                "Уведомления настраиваются в config/config.json (email, Telegram)."
            ),
            justify=tk.LEFT,
        )
        info.pack(anchor="w", padx=12, pady=12)

    def _bind_app_events(self) -> None:
        self.app.on_packet(self._on_live_packet)
        self.app.on_stats(self._on_stats_update)
        self.app.on_alert(self._on_alert)

    def _toggle_demo(self) -> None:
        self.app.set_demo_mode(self.demo_var.get())

    def _start_capture(self) -> None:
        self.app.capture.bpf_filter = self.bpf_var.get()
        iface = self.iface_var.get()
        self.app.capture.interface = iface if iface and iface != "demo" else None
        self.app.start_capture()
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)

    def _stop_capture(self) -> None:
        self.app.stop_capture()
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)

    def _on_live_packet(self, record: PacketRecord) -> None:
        def update():
            self.packet_tree.insert(
                "", 0,
                values=(
                    record.timestamp.strftime("%H:%M:%S"),
                    record.src_ip,
                    record.dst_ip,
                    record.src_port or "",
                    record.dst_port or "",
                    record.protocol,
                    record.size,
                    record.category,
                ),
            )
            children = self.packet_tree.get_children()
            if len(children) > 500:
                self.packet_tree.delete(children[-1])

        self.root.after(0, update)

    def _on_stats_update(self, stats) -> None:
        def update():
            self.lbl_packets.config(text=f"Пакетов: {stats.total_packets}")
            self.lbl_bytes.config(text=f"Объём: {self._fmt_bytes(stats.total_bytes)}")
            self.lbl_connections.config(text=f"Подключений: {stats.connection_count}")

        self.root.after(0, update)

    def _on_alert(self, alert) -> None:
        def update():
            self.alert_tree.insert(
                "", 0,
                values=(
                    alert.timestamp.strftime("%H:%M:%S"),
                    alert.level,
                    alert.message,
                ),
            )

        self.root.after(0, update)

    def _apply_filter(self) -> None:
        port = self.f_port.get().strip()
        dst_port = int(port) if port.isdigit() else None
        packets = self.app.analyzer.filter_packets(
            protocol=self.f_proto.get().strip().upper() or None,
            src_ip=self.f_src.get().strip() or None,
            dst_ip=self.f_dst.get().strip() or None,
            dst_port=dst_port,
            category=self.f_category.get().strip() or None,
            limit=100,
        )
        stats = self.app.analyzer.compute_stats(
            protocol=self.f_proto.get().strip().upper() or None,
            src_ip=self.f_src.get().strip() or None,
            dst_ip=self.f_dst.get().strip() or None,
            dst_port=dst_port,
            category=self.f_category.get().strip() or None,
        )

        lines = [
            f"Найдено пакетов: {len(packets)}",
            f"Общий объём: {self._fmt_bytes(stats.total_bytes)}",
            f"Подключений: {stats.connection_count}",
            "",
            "По протоколам:",
        ]
        for proto, vol in stats.by_protocol.items():
            lines.append(f"  {proto}: {self._fmt_bytes(vol)}")
        lines.append("\nПо категориям:")
        for cat, vol in stats.by_category.items():
            lines.append(f"  {cat}: {self._fmt_bytes(vol)}")
        lines.append("\nТоп источников:")
        for ip, vol in self.app.analyzer.top_talkers(top_n=5):
            lines.append(f"  {ip}: {self._fmt_bytes(vol)}")

        self.analysis_text.delete("1.0", tk.END)
        self.analysis_text.insert(tk.END, "\n".join(lines))

    def _generate_report(self) -> None:
        hours = int(self.report_period.get())
        end = datetime.now()
        start = end - timedelta(hours=hours)
        category = self.report_category.get().strip() or None
        fmt = self.report_format.get()

        try:
            path = self.app.generate_report(fmt, start, end, category)
            self.report_status.config(text=f"Отчёт создан: {path}")
            messagebox.showinfo("Отчёт", f"Отчёт сохранён:\n{path}")
        except Exception as exc:
            messagebox.showerror("Ошибка", str(exc))

    def _save_thresholds(self) -> None:
        try:
            self.app.update_thresholds(
                bytes_per_minute=int(self.thr_bytes.get()),
                connections_per_minute=int(self.thr_conn.get()),
                anomaly_z_score=float(self.thr_z.get()),
            )
            messagebox.showinfo("Настройки", "Пороги сохранены")
        except ValueError:
            messagebox.showerror("Ошибка", "Проверьте корректность числовых значений")

    def _show_demo_alert(self) -> None:
        self.app.emit_demo_alert()
        messagebox.showinfo(
            "Готово",
            "Тестовое предупреждение добавлено в журнал выше.",
        )

    def _test_notify(self) -> None:
        ok, msg = self.app.test_notifications()
        messagebox.showinfo("Email / Telegram", msg)

    def _reset_stats(self) -> None:
        self.app.reset_session_stats()
        self._on_stats_update(self.app.get_session_stats())

    def _clear_db(self) -> None:
        if messagebox.askyesno("Подтверждение", "Очистить все сохранённые данные?"):
            self.app.storage.clear()
            messagebox.showinfo("Готово", "База данных очищена")

    @staticmethod
    def _fmt_bytes(value: int) -> str:
        if value < 1024:
            return f"{value} B"
        if value < 1024 ** 2:
            return f"{value / 1024:.1f} KB"
        return f"{value / 1024 ** 2:.2f} MB"

    def run(self) -> None:
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self) -> None:
        self.app.stop_capture()
        self.root.destroy()
