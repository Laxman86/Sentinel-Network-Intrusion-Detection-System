from collections import defaultdict, deque
import time
from scapy.layers.inet import TCP
from ..utils.packet_utils import get_ip_tuple


class PortScanDetector:
    """
    Advanced Port Scan Detector
    - Uses distinct destination ports
    - Uses SYN ratio
    - Sliding time window
    - MEDIUM severity (reconnaissance)
    """

    def __init__(self, logger, window_sec=10, distinct_ports=20, min_syn_ratio=0.6):
        self.logger = logger
        self.window = window_sec
        self.distinct_ports_threshold = distinct_ports
        self.min_syn_ratio = min_syn_ratio

        # src -> deque[(timestamp, dport, is_syn)]
        self.events = defaultdict(deque)

        # Cool-down to prevent alert storms
        self.last_alert_time = defaultdict(float)

        # Sensor IP (ignore self-scans / responses)
        self.local_ip = "192.168.56.1"

    def on_packet(self, pkt):
        try:
            if not pkt.haslayer(TCP):
                return

            src, dst = get_ip_tuple(pkt)

            # Ignore localhost / sensor-generated traffic
            if not src or src == self.local_ip:
                return

            dport = int(pkt[TCP].dport)
            flags = pkt[TCP].flags
            is_syn = (int(flags) & 0x02) != 0  

            now = time.time()
            dq = self.events[src]
            dq.append((now, dport, is_syn))

            # Cleanup old events
            while dq and now - dq[0][0] > self.window:
                dq.popleft()

            ports = {p for (_, p, _) in dq}
            syns = sum(1 for (_, _, s) in dq if s)
            ratio = syns / max(len(dq), 1)

            # Cool-down (one alert per window per source)
            if now - self.last_alert_time[src] < self.window:
                return

            if (
                len(ports) >= self.distinct_ports_threshold
                and ratio >= self.min_syn_ratio
            ):
                self.logger.emit(
                    "PORT_SCAN",
                    src,
                    dst or "-",
                    {
                        "distinct_ports_in_window": len(ports),
                        "window_sec": self.window,
                        "syn_ratio": round(ratio, 2)
                    },
                    severity="MEDIUM"
                )
                self.last_alert_time[src] = now
                dq.clear()

        except Exception:
            pass