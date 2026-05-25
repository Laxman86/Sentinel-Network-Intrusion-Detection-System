import argparse
import json
import sys
from pathlib import Path

# -----------------------------
# Scapy import
# -----------------------------
try:
    from scapy.all import sniff
except Exception:
    sniff = None

# -----------------------------
# Imports (package-based)
# -----------------------------
from app.utils.logger import AlertLogger
from app.detectors.port_scan import PortScanDetector
from app.detectors.syn_flood import SynFloodDetector
from app.detectors.arp_spoof import ArpSpoofDetector
from app.detectors.icmp_sweep import IcmpSweepDetector


def build_detectors(logger, cfg):
    th = cfg.get("thresholds", {})
    return [
        PortScanDetector(logger, **th.get("Port_Scan", {})),
        SynFloodDetector(logger, **th.get("Syn_Flood", {})),
        ArpSpoofDetector(logger, **th.get("Arp_Spoof", {})),
        IcmpSweepDetector(logger, **th.get("Icmp_Sweep", {})),
    ]


def packet_handler(detectors, pkt):
    """
    Clean packet handler:
    - No debug spam
    - No silent swallowing of errors
    """
    for d in detectors:
        try:
            d.on_packet(pkt)
        except Exception as e:
            # Print once; does not crash backend
            print(f"[DETECTOR ERROR] {d.__class__.__name__}: {e}")


def main():
    ap = argparse.ArgumentParser(description="SentinelNIDS – Scapy-based Network IDS")
    ap.add_argument("--iface", default=None, help="Interface to sniff on")
    ap.add_argument("--bpf-filter", default=None, help="BPF capture filter")
    ap.add_argument("--log-dir", default=None, help="Directory to write alert logs")
    ap.add_argument("--config", default=str(Path(__file__).with_name("config.json")))
    args = ap.parse_args()

    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))

    # interface for demo reliability
    iface = args.iface or "Ethernet 3"

    # Capture what actually detect
    bpf = args.bpf_filter or "arp or icmp or tcp"

    log_dir = args.log_dir or cfg.get("log_dir", "logs")

    logger = AlertLogger(log_dir)
    detectors = build_detectors(logger, cfg)

    if sniff is None:
        print("Scapy is not installed.")
        sys.exit(1)

    print(f"[NIDS] sniffing on iface={iface} filter='{bpf}' log_dir={log_dir}")

    try:
        sniff(
            iface=iface,
            filter=bpf,
            prn=lambda p: packet_handler(detectors, p),
            store=False
        )
    except PermissionError:
        print("Permission error: run as Administrator.")
    except KeyboardInterrupt:
        print("[NIDS] stopped")


if __name__ == "__main__":
    main()