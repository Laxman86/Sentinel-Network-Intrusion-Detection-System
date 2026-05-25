@echo off
setlocal
cd /d %~dp0

echo === NIDS Runner ===

if not exist .venv (
  python -m venv .venv
)
call .venv\Scripts\activate
python -m pip install --upgrade pip >nul
pip install -r requirements.txt >nul

echo.
set /p IFACE=Enter interface name (blank=auto): 
set /p LOGDIR=Enter log directory [logs]: 
if "%LOGDIR%"=="" set LOGDIR=logs
set /p BPF=Enter BPF filter [tcp or arp or icmp or udp port 53]: 
if "%BPF%"=="" set BPF=tcp or arp or icmp or udp port 53

echo.
echo Starting NIDS... (Run CMD as Administrator if capture fails)
if "%IFACE%"=="" (
  python code\nids_main.py --log-dir "%LOGDIR%" --bpf-filter "%BPF%"
) else (
  python code\nids_main.py --iface "%IFACE%" --log-dir "%LOGDIR%" --bpf-filter "%BPF%"
)
endlocal
