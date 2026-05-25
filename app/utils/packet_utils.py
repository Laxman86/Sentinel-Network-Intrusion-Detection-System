from typing import Optional, Tuple


def get_ip_tuple(pkt) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract source and destination IP address from IPv4 / IPv6 packet.
    """
    src = dst = None
    try:
        if pkt.haslayer("IP"):
            src, dst = pkt["IP"].src, pkt["IP"].dst
        elif pkt.haslayer("IPv6"):
            src, dst = pkt["IPv6"].src, pkt["IPv6"].dst
    except Exception:
        pass
    return src, dst


def get_port_tuple(pkt) -> Tuple[Optional[int], Optional[int]]:
    """
    Extract source and destination ports from TCP or UDP packet.
    Returns (sport, dport) or (None, None).
    """
    try:
        if pkt.haslayer("TCP"):
            return pkt["TCP"].sport, pkt["TCP"].dport
        if pkt.haslayer("UDP"):
            return pkt["UDP"].sport, pkt["UDP"].dport
    except Exception:
        pass
    return None, None