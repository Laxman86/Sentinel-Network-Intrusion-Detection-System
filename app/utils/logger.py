import csv
import json
import datetime
from pathlib import Path
from typing import Dict, Any


class AlertLogger:
    def __init__(self, log_dir: str = "logs"):
        self.base = Path(log_dir)
        self.base.mkdir(parents=True, exist_ok=True)

        self.jsonl = self.base / "alerts.jsonl"
        self.csvp = self.base / "alerts.csv"

        # Initialize CSV header only once
        if not self.csvp.exists():
            with self.csvp.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "time",
                        "severity",
                        "type",
                        "src",
                        "dst",
                        "details"
                    ]
                )
                writer.writeheader()

    def emit(
        self,
        alert_type: str,
        src: str,
        dst: str,
        details: Dict[str, Any],
        severity: str = "MEDIUM"
    ):
        now = datetime.datetime.utcnow().isoformat() + "Z"

        rec = {
            "time": now,
            "severity": severity,
            "type": alert_type,
            "src": src,
            "dst": dst,
            "details": details
        }

        # Write JSONL log (for GUI + SIEM-style ingestion)
        with self.jsonl.open("a", encoding="utf-8") as jf:
            jf.write(json.dumps(rec) + "\n")

        # Write CSV log (for reporting/export)
        with self.csvp.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "time",
                    "severity",
                    "type",
                    "src",
                    "dst",
                    "details"
                ]
            )
            writer.writerow({
                **rec,
                "details": json.dumps(details)
            })

        # Console output (useful during demo/testing)
        print(f"[{severity}] {now} {alert_type} {src} -> {dst} | {details}")