from collections import defaultdict, deque
import time
from ..utils.packet_utils import get_ip_tuple, get_port_tuple


class SynFloodDetector:
    def __init__(self, logger, window_sec=5, syn_per_src=100, ack_expect_ratio=0.05):
        self.logger = logger
        self.window = window_sec
        self.syn_limit = syn_per_src
        self.ack_ratio = ack_expect_ratio

        # Track SYNs and ACKs with port context
        self.syn_events = defaultdict(deque)
        self.ack_events = defaultdict(deque)

        # Cool-down to prevent alert storms
        self.last_alert_time = defaultdict(float)

    def on_packet(self, pkt):
        try:
            if not pkt.haslayer("TCP"):
                return

            src, dst = get_ip_tuple(pkt)
            sport, dport = get_port_tuple(pkt)
            if not src or not dport:
                return

            flags = pkt["TCP"].flags
            now = time.time()
            key = (src, dst)

            # Track SYN packets
            if flags & 0x02:  
                self.syn_events[key].append((now, dport))

            # Track ACK packets
            if flags & 0x10:  
                self.ack_events[key].append(now)

            # Cleanup old events
            while self.syn_events[key] and now - self.syn_events[key][0][0] > self.window:
                self.syn_events[key].popleft()

            while self.ack_events[key] and now - self.ack_events[key][0] > self.window:
                self.ack_events[key].popleft()

            syn_count = len(self.syn_events[key])
            ack_count = len(self.ack_events[key])
            ratio = ack_count / max(syn_count, 1)

            # Distinct destination ports (scan vs flood separation)
            distinct_ports = {p for (_, p) in self.syn_events[key]}

            # If multiple ports → port scan detector handles it
            if len(distinct_ports) > 2:
                return

            # Cool-down: one alert per window per source-destination
            if now - self.last_alert_time[key] < self.window:
                return

            if syn_count >= self.syn_limit and ratio <= self.ack_ratio:
                self.logger.emit(
                    "SYN_FLOOD",
                    src,
                    dst,
                    {
                        "syn_in_window": syn_count,
                        "ack_in_window": ack_count,
                        "window_sec": self.window,
                        "ack_to_syn_ratio": round(ratio, 3),
                        "target_port": list(distinct_ports)[0]
                    },
                    severity="HIGH"
                )

                self.last_alert_time[key] = now
                self.syn_events[key].clear()
                self.ack_events[key].clear()

        except Exception:
            pass