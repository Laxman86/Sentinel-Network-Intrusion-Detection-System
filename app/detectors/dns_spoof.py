import time


class DnsSpoofDetector:
    def __init__(self, logger, authorized_dns_servers=None, track_ttl_anomaly=True):
        self.logger = logger

        authorized_dns_servers = authorized_dns_servers or []
        self.authorized_dns = {self._normalize_ip(x) for x in authorized_dns_servers if x}

        self.track_ttl = track_ttl_anomaly

        self.last_ttls = {}
        self.last_alert_time = {}
        self.cooldown_sec = 10

        self.min_prev_ttl = 300
        self.ttl_drop_ratio = 0.10
        self.ttl_floor = 60

    def _normalize_ip(self, ip: str) -> str:
        if not ip:
            return ""
        ip = ip.strip().lower()
        if "%" in ip:
            ip = ip.split("%", 1)[0]
        return ip

    def _get_src_ip(self, pkt):
        if pkt.haslayer("IP"):
            return pkt["IP"].src
        if pkt.haslayer("IPv6"):
            return pkt["IPv6"].src
        return None

    def on_packet(self, pkt):
        try:
            if not pkt.haslayer("DNS"):
                return

            dns = pkt["DNS"]
            if dns.qr != 1:
                return

            src_ip_raw = self._get_src_ip(pkt)
            if not src_ip_raw:
                return

            src_ip = self._normalize_ip(src_ip_raw)
            now = time.time()

            # -------------------------------------------------
            # DEMO SAFE TRIGGER (DNS response visibility)
            # -------------------------------------------------
            last_demo = self.last_alert_time.get("demo", 0)
            if now - last_demo >= self.cooldown_sec:
                self.last_alert_time["demo"] = now
                self.logger.emit(
                    "DNS_SPOOF",
                    src_ip_raw,
                    "-",
                    {
                        "mode": "demo",
                        "reason": "DNS response detected (demo-safe trigger)"
                    },
                    severity="HIGH"
                )

            # -------------------------------------------------
            # 1. Unauthorized DNS source check
            # -------------------------------------------------
            if self.authorized_dns and src_ip not in self.authorized_dns:
                last = self.last_alert_time.get(src_ip, 0)
                if now - last >= self.cooldown_sec:
                    self.last_alert_time[src_ip] = now
                    self.logger.emit(
                        "DNS_SPOOF",
                        src_ip_raw,
                        "-",
                        {
                            "mode": "unauthorized-source",
                            "normalized_src": src_ip
                        },
                        severity="HIGH"
                    )

            # -------------------------------------------------
            # 2. TTL anomaly detection (advanced logic preserved)
            # -------------------------------------------------
            if not self.track_ttl:
                return

            try:
                if dns.ancount > 0 and hasattr(dns, "qd") and hasattr(dns.qd, "qname") and hasattr(dns, "an"):
                    qname = dns.qd.qname.decode(errors="ignore")
                    ttl = int(getattr(dns.an, "ttl", 0))

                    prev = self.last_ttls.get(qname)

                    if prev is not None and prev >= self.min_prev_ttl and ttl > 0:
                        if self.ttl_floor == 0 or ttl <= self.ttl_floor:
                            if ttl < prev * self.ttl_drop_ratio:
                                last = self.last_alert_time.get(qname, 0)
                                if now - last >= self.cooldown_sec:
                                    self.last_alert_time[qname] = now
                                    self.logger.emit(
                                        "DNS_SPOOF",
                                        src_ip_raw,
                                        qname,
                                        {
                                            "mode": "ttl-anomaly",
                                            "previous_ttl": prev,
                                            "current_ttl": ttl,
                                            "rule": f"current < {int(self.ttl_drop_ratio*100)}% of previous "
                                                    f"and previous >= {self.min_prev_ttl}"
                                        },
                                        severity="HIGH"
                                    )

                    if ttl > 0:
                        self.last_ttls[qname] = ttl

            except Exception:
                pass

        except Exception:
            pass