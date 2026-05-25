#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
python -m pip install --upgrade pip -q
pip install -r requirements.txt -q

echo "
=== NIDS Runner ==="
read -r -p "Enter interface name (blank=auto): " IFACE
read -r -p "Enter log directory [logs]: " LOGDIR
LOGDIR=${LOGDIR:-logs}
read -r -p "Enter BPF filter [tcp or arp or icmp or udp port 53]: " BPF
BPF=${BPF:-"tcp or arp or icmp or udp port 53"}

echo "
Starting NIDS... (use sudo if you get permission error)"
if [ -z "$IFACE" ]; then
  python code/nids_main.py --log-dir "$LOGDIR" --bpf-filter "$BPF"
else
  python code/nids_main.py --iface "$IFACE" --log-dir "$LOGDIR" --bpf-filter "$BPF"
fi
