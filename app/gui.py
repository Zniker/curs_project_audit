from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QTableWidget, QTableWidgetItem,
    QAbstractItemView, QLineEdit, QMessageBox, QHeaderView, QSplitter
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPen

from PyQt6.QtCharts import (
    QChart, QChartView, QPieSeries, QLineSeries,
    QValueAxis
)

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from .models import Base, AuditEvent


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # --- DB ---
        self.engine = create_engine("sqlite:///audit.db")
        Base.metadata.bind = self.engine

        self.setWindowTitle("SOC-панель: аудит критических файлов Linux")
        self.resize(1400, 750)

        # --- Тёмная тема ---
        self.setStyleSheet("""
        QMainWindow {
            background-color: #0f1115;
            color: #f0f0f0;
        }
        QLabel {
            color: #f0f0f0;
        }
        QLineEdit, QComboBox, QPushButton {
            background-color: #1c1f26;
            color: #f0f0f0;
            border: 1px solid #444a55;
            padding: 2px 6px;
            border-radius: 3px;
        }
        QPushButton:hover {
            background-color: #262b36;
        }
        QTableWidget {
            background-color: #13151a;
            color: #f0f0f0;
            gridline-color: #30343d;
            selection-background-color: #394b70;
            selection-color: #ffffff;
            alternate-background-color: #181b22;
        }
        QHeaderView::section {
            background-color: #1a1d24;
            color: #f0f0f0;
            padding: 3px;
            border: 1px solid #30343d;
        }
        """)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)

        # --- Заголовок + KPI ---
        title_layout = QHBoxLayout()
        main_layout.addLayout(title_layout)

        title = QLabel("SOC-панель: аудит критических файлов Linux")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        title_layout.addWidget(title)

        title_layout.addStretch()

        self.kpi_total = QLabel("Всего: 0")
        self.kpi_susp = QLabel("Подозрительных: 0")
        self.kpi_crit = QLabel("Критичных: 0")

        for lbl, color in [
            (self.kpi_total, "#3b82f6"),
            (self.kpi_susp, "#f59e0b"),
            (self.kpi_crit, "#ef4444"),
        ]:
            lbl.setStyleSheet(
                f"background-color: {color}33; border: 1px solid {color}; "
                "padding: 4px 8px; border-radius: 4px; font-size: 11px;"
            )
            title_layout.addWidget(lbl)

        # --- Панель фильтров ---
        controls_layout = QHBoxLayout()
        main_layout.addLayout(controls_layout)

        controls_layout.addWidget(QLabel("Классификация:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("Все", userData=None)
        self.filter_combo.addItem("Только подозрительные", userData="suspicious")
        self.filter_combo.addItem("Только нормальные", userData="normal")
        controls_layout.addWidget(self.filter_combo)

        # Фильтр по типу события
        controls_layout.addSpacing(15)
        controls_layout.addWidget(QLabel("Тип:"))
        self.type_combo = QComboBox()
        self.type_combo.addItem("Все типы", userData=None)
        self.type_combo.addItem("accounts", userData="accounts")
        self.type_combo.addItem("privilege", userData="privilege")
        self.type_combo.addItem("remote_access", userData="remote_access")
        self.type_combo.addItem("logging", userData="logging")
        controls_layout.addWidget(self.type_combo)

        controls_layout.addSpacing(15)
        controls_layout.addWidget(QLabel("UID:"))
        self.uid_edit = QLineEdit()
        self.uid_edit.setPlaceholderText("например 1000, пусто = все")
        self.uid_edit.setFixedWidth(170)
        controls_layout.addWidget(self.uid_edit)

        controls_layout.addStretch()
        self.refresh_button = QPushButton("Обновить")
        controls_layout.addWidget(self.refresh_button)

        # --- Основная область: таблица + графики ---
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)

        # Левая часть — таблица
        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(
            ["ID", "Время", "UID", "AUID",
             "Процесс", "Файл", "Тип", "Уровень", "Классификация"]
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)

        splitter.addWidget(self.table)

        # Правая часть — графики
        charts_container = QWidget()
        charts_layout = QVBoxLayout(charts_container)
        charts_layout.setContentsMargins(4, 0, 0, 0)

        self.time_chart_view = QChartView()
        charts_layout.addWidget(self.time_chart_view, stretch=2)

        self.pie_chart_view = QChartView()
        charts_layout.addWidget(self.pie_chart_view, stretch=1)

        splitter.addWidget(charts_container)
        splitter.setSizes([900, 500])

        # --- Сигналы ---
        self.refresh_button.clicked.connect(self.load_data)
        self.filter_combo.currentIndexChanged.connect(self.load_data)
        self.type_combo.currentIndexChanged.connect(self.load_data)
        self.uid_edit.returnPressed.connect(self.load_data)
        self.table.cellDoubleClicked.connect(self.show_details)

        # Первая загрузка
        self.load_data()

    # ------------------------ ЛОГИКА ------------------------

    def load_data(self):
        """Загрузка событий в таблицу + обновление KPI и графиков."""
        classification = self.filter_combo.currentData()
        uid_filter = self.uid_edit.text().strip() or None
        event_type_filter = self.type_combo.currentData()

        with Session(self.engine) as session:
            stmt = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1000)
            if classification:
                stmt = stmt.where(AuditEvent.classification == classification)
            if uid_filter:
                stmt = stmt.where(AuditEvent.uid == uid_filter)
            if event_type_filter:
                stmt = stmt.where(AuditEvent.event_type == event_type_filter)
            events = session.scalars(stmt).all()

        self.table.setRowCount(len(events))

        total = len(events)
        susp_count = 0
        crit_count = 0

        for row, e in enumerate(events):
            # Уровень
            level = "OK"
            if e.classification == "suspicious":
                if e.perm and "w" in (e.perm or ""):
                    level = "CRITICAL"
                else:
                    level = "WARNING"

            if e.classification == "suspicious":
                susp_count += 1
                if level == "CRITICAL":
                    crit_count += 1

            self.table.setItem(row, 0, QTableWidgetItem(str(e.id)))
            self.table.setItem(row, 1, QTableWidgetItem(str(e.timestamp)))
            self.table.setItem(row, 2, QTableWidgetItem(str(e.uid or "")))
            self.table.setItem(row, 3, QTableWidgetItem(str(e.auid or "")))
            self.table.setItem(row, 4, QTableWidgetItem(str(e.exe or "")))
            self.table.setItem(row, 5, QTableWidgetItem(str(e.file_path or "")))
            self.table.setItem(row, 6, QTableWidgetItem(str(e.event_type or "")))
            self.table.setItem(row, 7, QTableWidgetItem(level))
            self.table.setItem(row, 8, QTableWidgetItem(str(e.classification or "")))

            # Цвет по уровню — тёмные оттенки
            if level == "CRITICAL":
                bg = QColor("#7f1d1d")   # тёмно-красный
            elif level == "WARNING":
                bg = QColor("#78350f")   # тёмно-оранжевый
            else:
                bg = QColor("#064e3b")   # тёмно-зелёный

            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item:
                    item.setBackground(bg)

        self.table.resizeColumnsToContents()

        # KPI
        self.kpi_total.setText(f"Всего: {total}")
        self.kpi_susp.setText(f"Подозрительных: {susp_count}")
        self.kpi_crit.setText(f"Критичных: {crit_count}")

        # Графики
        self.update_charts(events)

    def update_charts(self, events):
        """Обновить time-series и pie-chart по событиям (ось X = индекс события)."""
        # --- Pie-chart: распределение по уровням ---
        normal = 0
        warn = 0
        crit = 0

        for e in events:
            if e.classification != "suspicious":
                normal += 1
            else:
                if e.perm and "w" in (e.perm or ""):
                    crit += 1
                else:
                    warn += 1

        pie_series = QPieSeries()
        if normal:
            pie_series.append("Normal", normal)
            pie_series.slices()[-1].setColor(QColor("#22c55e"))
        if warn:
            pie_series.append("Warning", warn)
            pie_series.slices()[-1].setColor(QColor("#eab308"))
        if crit:
            pie_series.append("Critical", crit)
            pie_series.slices()[-1].setColor(QColor("#ef4444"))

        pie_chart = QChart()
        if normal or warn or crit:
            pie_chart.addSeries(pie_series)
        pie_chart.setTitle("Распределение событий по уровню")
        pie_chart.setBackgroundVisible(False)
        pie_chart.legend().setLabelColor(QColor("#f0f0f0"))
        pie_chart.legend().setVisible(True)
        pie_chart.legend().setAlignment(Qt.AlignmentFlag.AlignBottom)
        self.pie_chart_view.setChart(pie_chart)
        self.pie_chart_view.setStyleSheet("background-color: #13151a;")

        # --- Time-series: индекс события по X, накопленное количество по Y ---
        total_series = QLineSeries()
        susp_series = QLineSeries()

        total_series.setName("Все события")
        susp_series.setName("Подозрительные")

        total_pen = QPen(QColor("#22c55e"))
        total_pen.setWidth(2)
        total_series.setPen(total_pen)

        susp_pen = QPen(QColor("#ef4444"))
        susp_pen.setWidth(2)
        susp_series.setPen(susp_pen)

        total_series.setPointsVisible(True)
        susp_series.setPointsVisible(True)

        total_cnt = 0
        susp_cnt = 0

        events_sorted = sorted(events, key=lambda e: e.timestamp or 0)

        for idx, e in enumerate(events_sorted, start=1):
            x = float(idx)       # просто номер события
            total_cnt += 1
            total_series.append(x, float(total_cnt))
            if e.classification == "suspicious":
                susp_cnt += 1
                susp_series.append(x, float(susp_cnt))

        time_chart = QChart()
        time_chart.setTitle("Динамика событий (зелёный — все, красный — suspicious)")
        time_chart.setBackgroundVisible(False)
        time_chart.legend().setVisible(True)
        time_chart.legend().setLabelColor(QColor("#f0f0f0"))

        time_chart.addSeries(total_series)
        time_chart.addSeries(susp_series)

        max_x = max(1, len(events_sorted))
        max_y = max(1, total_cnt, susp_cnt)

        axis_x = QValueAxis()
        axis_x.setTitleText("Номер события (по времени)")
        axis_x.setLabelsColor(QColor("#e5e7eb"))
        axis_x.setRange(1.0, float(max_x))

        axis_y = QValueAxis()
        axis_y.setTitleText("Накопленное количество событий")
        axis_y.setLabelsColor(QColor("#e5e7eb"))
        axis_y.setRange(0.0, float(max_y))

        time_chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        time_chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)

        total_series.attachAxis(axis_x)
        total_series.attachAxis(axis_y)
        susp_series.attachAxis(axis_x)
        susp_series.attachAxis(axis_y)

        self.time_chart_view.setChart(time_chart)
        self.time_chart_view.setStyleSheet("background-color: #13151a;")

    def show_details(self, row, column):
        """Подробности события по двойному клику."""
        item = self.table.item(row, 0)
        if not item:
            return

        event_id = int(item.text())

        with Session(self.engine) as session:
            e = session.get(AuditEvent, event_id)

        if not e:
            return

        text = (
            f"ID: {e.id}\n"
            f"Время: {e.timestamp}\n"
            f"UID: {e.uid}\n"
            f"AUID: {e.auid}\n"
            f"Процесс: {e.exe}\n"
            f"Команда (comm): {e.comm}\n"
            f"Системный вызов: {e.syscall}\n"
            f"Файл: {e.file_path}\n"
            f"Тип события: {e.event_type}\n"
            f"Права (perm): {e.perm}\n"
            f"Ключ (key): {e.key}\n"
            f"Успех: {e.success}\n"
            f"Классификация: {e.classification}\n"
            f"Причина: {e.reason}"
        )

        msg = QMessageBox(self)
        msg.setWindowTitle("Подробности события")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText(text)
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)

        msg.setStyleSheet("""
            QMessageBox {
                background-color: #13151a;
            }
            QLabel {
                color: #f0f0f0;
            }
            QPushButton {
                background-color: #1c1f26;
                color: #f0f0f0;
                border: 1px solid #444a55;
                padding: 2px 10px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #262b36;
            }
        """)

        msg.exec()
