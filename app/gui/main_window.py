import os
import json

from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QTextEdit,
    QTableWidget, QTableWidgetItem,
    QComboBox, QFileDialog
)
from PyQt5.QtCore import Qt, QTimer

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
from matplotlib.figure import Figure

from app.gui.nids_thread import NIDSThread


# ======================================================
# Attack Statistics Bar Chart
# ======================================================
class AttackChart(FigureCanvasQTAgg):
    def __init__(self):
        self.figure = Figure(figsize=(5, 3))
        self.ax = self.figure.add_subplot(111)
        super().__init__(self.figure)

        self.counts = {
            "ARP_SPOOF": 0,
            "SYN_FLOOD": 0,
            "PORT_SCAN": 0,
            "ICMP_SWEEP": 0,
        }
        self.refresh()

    def increment(self, attack_type):
        if attack_type in self.counts:
            self.counts[attack_type] += 1
            self.refresh()

    def refresh(self):
        self.ax.clear()
        self.ax.bar(self.counts.keys(), self.counts.values(), color="Steelblue")
        self.ax.set_title("Attack Statistics")
        self.ax.set_ylabel("Attack Count")
        self.figure.tight_layout()
        self.draw()


# ======================================================
# Main Dashboard Window
# ======================================================
class SentinelDashboard(QMainWindow):
    LOG_FILE = "logs/alerts.jsonl"

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SentinelNIDS – Network Intrusion Detection Dashboard")
        self.resize(1000, 700)

        self.nids_thread = None
        self.all_alerts = []
        self.monitoring_enabled = False

        self._init_ui()

        self.alert_timer = QTimer()
        self.alert_timer.timeout.connect(self.process_alerts)
        self.alert_timer.start(500)

    # ==================================================
    # UI Layout
    # ==================================================
    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        # ---------- Header ----------
        logo = QLabel()
        pixmap = QPixmap("app/gui/assets/sentinel_logo.png").scaled(
            48, 48, Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        logo.setPixmap(pixmap)

        title = QLabel("SentinelNIDS")
        title.setStyleSheet("font-size:18px; font-weight:bold;")
        title.setAlignment(Qt.AlignVCenter)

        self.status_label = QLabel("Status: Offline")
        self.status_label.setStyleSheet("color:red; font-weight:bold")

        header = QHBoxLayout()
        header.addWidget(logo)
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.status_label)

        # ---------- Controls ----------
        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.setStyleSheet("color:Green")
        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.setStyleSheet("color:Red")
        self.stop_btn.setEnabled(False)

        self.export_csv_btn = QPushButton("Export CSV")
        self.export_json_btn = QPushButton("Export JSON")

        self.start_btn.clicked.connect(self.start_monitoring)
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.export_csv_btn.clicked.connect(self.export_csv)
        self.export_json_btn.clicked.connect(self.export_json)

        controls = QHBoxLayout()
        controls.addWidget(self.start_btn)
        controls.addWidget(self.stop_btn)
        controls.addStretch()
        controls.addWidget(self.export_csv_btn)
        controls.addWidget(self.export_json_btn)

        #---------High Risk alert-----------
        # self.high_risk_alert = QLabel("HIGH RISK ALERT: No critical alerts detected")
        # self.high_risk_alert.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        # self.high_risk_alert.setFixedHeight(58)
        # self.high_risk_alert.setStyleSheet("""
        #     background-color: red;
        #     color: white;
        #     font-size: 16px; 
        #     font-weight: bold; 
        #     padding: 10px;
        # border-radius: 5px;
        # """)

        # ---------- Filter ----------
        self.filter_box = QComboBox()
        self.filter_box.addItems([
            "ALL", "ARP SPOOF", "SYN FLOOD",
            "PORT SCAN", "ICMP SWEEP"
        ])
        self.filter_box.currentTextChanged.connect(self.apply_filter)

        # ---------- Alert Stream ----------
        self.alert_stream = QTextEdit()
        self.alert_stream.setReadOnly(True)
        self.alert_stream.setStyleSheet("font-family: Consolas, monospace; font-size:11px;")

        # ---------- Alert Table ----------
        self.alert_table = QTableWidget(0, 6)
        self.alert_table.setHorizontalHeaderLabels(
            ["Date-Timeline", "Severity", "Type", "Source IP", "Destination IP", "Details"]
        )
        self.alert_table.setColumnWidth(0, 220)
        self.alert_table.setColumnWidth(1, 100)
        self.alert_table.setColumnWidth(2, 130)
        self.alert_table.setColumnWidth(3, 130)
        self.alert_table.setColumnWidth(4, 130)
        self.alert_table.horizontalHeader().setStretchLastSection(True)
        self.alert_table.verticalHeader().setVisible(False)

        # ---------- Chart ----------
        self.attack_chart = AttackChart()

        # ---------- Layout ----------
        main_layout = QVBoxLayout()
        main_layout.addLayout(header)
        main_layout.addLayout(controls)
        main_layout.addWidget(self.filter_box)
        main_layout.addWidget(self.attack_chart)
        main_layout.addWidget(self.alert_stream)
        main_layout.addWidget(self.alert_table)
        # main_layout.addWidget(self.high_risk_alert)
        central.setLayout(main_layout)
                      
    # ==================================================
    # Start / Stop Monitoring
    # ==================================================
    def start_monitoring(self):
        self.monitoring_enabled = True

        if not self.nids_thread:
            self.nids_thread = NIDSThread()
            self.nids_thread.start()

        self.status_label.setText("Status: Online")
        self.status_label.setStyleSheet("color:green; font-weight:bold")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_monitoring(self):
        self.monitoring_enabled = False
        self.status_label.setText("Status: Offline")
        self.status_label.setStyleSheet("color:red; font-weight:bold")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        self.alert_stream.clear()
        self.alert_table.setRowCount(0)
        self.attack_chart.counts = {k: 0 for k in self.attack_chart.counts}
        self.attack_chart.refresh()

    # ==================================================
    # Read alerts from log file
    # ==================================================
    def process_alerts(self):
        if not self.monitoring_enabled:
            return

        if not os.path.exists(self.LOG_FILE):
            return

        with open(self.LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        MAX_ALERTS_PER_TICK = 10
        new_lines = lines[len(self.all_alerts):][:MAX_ALERTS_PER_TICK]

        for line in new_lines:
            try:
                rec = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            self.all_alerts.append(rec)

            self.alert_stream.append(
                f"[{rec['time']}] [{rec['severity']}] {rec['type']} from {rec['src']}"
            )

            self.attack_chart.increment(rec["type"])

        self.apply_filter()

    # ==================================================
    # Filter
    # ==================================================
    def apply_filter(self):
        self.alert_table.setRowCount(0)
        selected = self.filter_box.currentText()

        for rec in self.all_alerts:
            if selected == "ALL" or rec["type"] == selected:
                self.add_table_row(rec)

    def add_table_row(self, rec):
        row = self.alert_table.rowCount()
        self.alert_table.insertRow(row)

        self.alert_table.setItem(row, 0, QTableWidgetItem(rec["time"]))

        sev_item = QTableWidgetItem(rec["severity"])
        if rec["severity"] == "HIGH":
            sev_item.setForeground(Qt.red)
        elif rec["severity"] == "MEDIUM":
            sev_item.setForeground(Qt.darkYellow)
        else:
            sev_item.setForeground(Qt.gray)

        self.alert_table.setItem(row, 1, sev_item)
        self.alert_table.setItem(row, 2, QTableWidgetItem(rec["type"]))
        self.alert_table.setItem(row, 3, QTableWidgetItem(rec["src"]))
        self.alert_table.setItem(row, 4, QTableWidgetItem(rec["dst"]))
        self.alert_table.setItem(row, 5, QTableWidgetItem(str(rec["details"])))

        # self.alert_table.scrollToBottom()

    # ==================================================
    # Export
    # ==================================================
    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "", "CSV Files (*.csv)")
        if not path:
            return

        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["time", "severity", "type", "src", "dst", "details"]
            )
            writer.writeheader()
            for rec in self.all_alerts:
                writer.writerow(rec)

    def export_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "", "JSON Files (*.json)")
        if not path:
            return

        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.all_alerts, f, indent=4)