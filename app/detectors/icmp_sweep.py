from collections import defaultdict, deque
import time
from ..utils.packet_utils import get_ip_tuple


class IcmpSweepDetector:
    def __init__(
        self,
        logger,
        window_sec=10,
        distinct_targets=15,
        rate_threshold=20
    ):
        self.logger = logger
        self.window = window_sec
        self.target_threshold = distinct_targets
        self.rate_threshold = rate_threshold
        self.events = defaultdict(deque)

        # Cool-down tracking (CRITICAL)
        self.last_alert_time = defaultdict(float)

    def on_packet(self, pkt):
        try:
            if not pkt.haslayer("ICMP"):
                return

            # Only ICMP Echo Request
            if int(pkt["ICMP"].type) != 8:
                return

            src, dst = get_ip_tuple(pkt)
            if not src or not dst:
                return

            now = time.time()
            dq = self.events[src]
            dq.append((now, dst))

            #  Remove old packets
            while dq and now - dq[0][0] > self.window:
                dq.popleft()

            distinct = {d for (_, d) in dq}

            #  Global cool-down (1 alert per window per source)
            if now - self.last_alert_time[src] < self.window:
                return

            # MODE 1: Horizontal sweep (enterprise networks)
            if len(distinct) >= self.target_threshold:
                self.logger.emit(
                    "ICMP_SWEEP",
                    src,
                    "-",
                    {
                        "mode": "horizontal",
                        "distinct_targets": len(distinct),
                        "window_sec": self.window
                    },
                    severity="MEDIUM"
                )
                self.last_alert_time[src] = now
                dq.clear()
                return

            # MODE 2: High-rate ICMP to single host (lab/demo)
            if len(dq) >= self.rate_threshold:
                self.logger.emit(
                    "ICMP_SWEEP",
                    src,
                    dst,
                    {
                        "mode": "rate-based",
                        "packet_count": len(dq),
                        "window_sec": self.window
                    },
                    severity="MEDIUM"
                )
                self.last_alert_time[src] = now
                dq.clear()

        except Exception:
            pass