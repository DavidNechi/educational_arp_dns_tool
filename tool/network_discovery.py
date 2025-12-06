# tool/network_discovery.py

from scapy.all import ARP, Ether, srp


class NetworkDiscovery:
    """
    Simple ARP-based network discovery for a lab network.
    """

    def __init__(self, ip_range: str = "192.168.56.0/24"):
        # I assume a host-only / lab network by default.
        self.ip_range = ip_range
        self.discovered_hosts = []  # {"ip", "mac"}

    def scan_arp_range(self) -> None:
        """
        Perform an ARP scan over self.ip_range and fill self.discovered_hosts.
        """
        print(f"[i] Starting ARP scan on range: {self.ip_range}")

        # Ethernet frame with broadcast destination MAC.
        # ff:ff:ff:ff:ff:ff = "send to everyone" on the local network.
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")

        # ARP request: who-has <target-IP> tell <my-IP> (Scapy fills some fields for us).
        arp = ARP(pdst=self.ip_range)

        # Stack layers: L2 (Ethernet) / L3-protocol (ARP).
        packet = ether / arp

        # srp = send and receive packets at L2.
        # timeout=2 is arbitrary but enough for a small lab.
        # verbose=False to keep output clean for students.
        ans, _ = srp(packet, timeout=2, verbose=False)

        # Clear any previous results before filling
        self.discovered_hosts = []

        for sent, received in ans:
            host_info = {
                "ip": received.psrc,   # source IP in ARP reply
                "mac": received.hwsrc  # source MAC in ARP reply
            }
            self.discovered_hosts.append(host_info)

        print(f"[i] ARP scan finished, found {len(self.discovered_hosts)} hosts.")

    def print_results(self) -> None:
        """
        Print a simple ASCII table of discovered hosts.
        """
        if not self.discovered_hosts:
            print("[!] No hosts discovered yet. Did you run scan_arp_range()?")
            return

        print("\n[*] Discovered hosts on the lab network:")
        print("    IP address        MAC address")
        print("    --------------    -----------------")
        for host in self.discovered_hosts:
            # Keeping formatting super simple and readable
            print(f"    {host['ip']:15}  {host['mac']}")
        print()


def run() -> None:
    """
    Entry point used by cli.py.
    This keeps cli.py clean and lets us treat this module as "one scenario".
    """
    # TODO: later we might read the IP range from CLI args instead of hardcoding.
    discovery = NetworkDiscovery(ip_range="192.168.56.0/24")

    # 1) Scan
    discovery.scan_arp_range()

    # 2) Show results
    discovery.print_results()
