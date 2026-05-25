# Network Intrusion Detection System (NIDS) — Minor Project

## Run (one-click)
- **Windows:** double-click `run_nids.bat` (run Command Prompt as Administrator if capture fails)
- **Linux/macOS:** `bash run_nids.sh` (use `sudo bash run_nids.sh` if capture fails)

## Run (manual)
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python code/nids_main.py --iface <iface> --log-dir logs
```

## Outputs
Alerts -> `logs/alerts.jsonl` and `logs/alerts.csv`

Generated: 2026-01-15 08:29
