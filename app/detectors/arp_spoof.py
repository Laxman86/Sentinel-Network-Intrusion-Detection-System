from collections import defaultdict, deque
import time
from scapy.layers.l2 import ARP


class ArpSpoofDetector:
    """
    Detects:
    1. ARP spoofing (multiple MACs claiming the same IP)
    2. Gratuitous ARP flooding (ARP anomalies)
    Severity: HIGH (MITM / integrity compromise)
    """

    def __init__(self, logger, max_macs_per_ip=1, window_sec=60, repeat_gratuitous_limit=5):
        self.logger = logger
        self.max_macs = max_macs_per_ip
        self.window = window_sec
        self.gratuitous_limit = repeat_gratuitous_limit

        self.ip_to_macs = defaultdict(set)
        self.gratuitous_counts = defaultdict(deque)

        #  Cooldown to prevent alert storms
        self.last_alert_time = defaultdict(float)

    def on_packet(self, pkt):
        try:
            if not pkt.haslayer(ARP):
                return

            arp = pkt[ARP]
            now = time.time()

            # -----------------------------
            # 1. ARP Spoof Detection
            # -----------------------------
            if arp.op == 2:  # ARP Reply
                ip = arp.psrc
                mac = arp.hwsrc

                self.ip_to_macs[ip].add(mac)

                if len(self.ip_to_macs[ip]) > self.max_macs:

                    # Cooldown: one alert per IP per window
                    if now - self.last_alert_time[ip] < self.window:
                        return

                    self.logger.emit(
                        "ARP_SPOOF",
                        mac,
                        ip,
                        {
                            "mode": "multiple-macs",
                            "ip": ip,
                            "macs_seen": list(self.ip_to_macs[ip]),
                            "max_macs_per_ip": self.max_macs
                        },
                        severity="HIGH"
                    )

                    self.last_alert_time[ip] = now
                    self.ip_to_macs[ip] = {mac}
                    return

            # -----------------------------
            # 2. Gratuitous ARP Flooding
            # -----------------------------
            if arp.psrc and arp.pdst and arp.psrc == arp.pdst:
                dq = self.gratuitous_counts[arp.psrc]
                dq.append(now)

                while dq and now - dq[0] > self.window:
                    dq.popleft()

                if len(dq) >= self.gratuitous_limit:

                    if now - self.last_alert_time[arp.psrc] < self.window:
                        return

                    self.logger.emit(
                        "ARP_SPOOF",
                        arp.hwsrc,
                        arp.psrc,
                        {
                            "mode": "gratuitous-arp",
                            "gratuitous_count_window": len(dq),
                            "window_sec": self.window
                        },
                        severity="HIGH"
                    )

                    self.last_alert_time[arp.psrc] = now
                    dq.clear()

        except Exception:
            pass