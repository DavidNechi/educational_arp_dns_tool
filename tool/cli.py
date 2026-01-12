import argparse
import ipaddress
from tool import network_discovery, arp_lab, dns_lab, ssl_strip


class _HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    """
    Combine defaults display with nice multiline epilog formatting.
    """
    pass


def _cidr(arg_value: str) -> str:
    try:
        ipaddress.ip_network(arg_value, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError("IP range must be in CIDR form like 192.168.1.0/24")
    return arg_value

def main():
    parser = argparse.ArgumentParser(
        description="Educational ARP & DNS Manipulation Lab Tool (authorized lab use only)",
        formatter_class=_HelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m tool.cli discover -r 192.168.178.0/24\n"
            "  python -m tool.cli arp-demo 192.168.178.1 192.168.178.63 -I eth0 -c 5 -i 1\n"
            "  python -m tool.cli dns-demo example.com -s 192.168.178.76 -I eth0\n"
            "  python -m tool.cli ssl-strip demo.local -b 192.168.178.76 -I eth0"
        ),
    )
    # Support the common-but-nonstandard '-help' in addition to -h/--help.
    parser.add_argument("-help", action="help", help="Show this help message and exit")

    sub = parser.add_subparsers(dest="cmd")

    discover_parser = sub.add_parser(
        "discover",
        help="ARP scan a subnet (use -r/--ip-range to set CIDR)",
        description="Perform an ARP broadcast sweep over a CIDR to find live hosts on a lab network.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    discover_parser.add_argument(
        "-r",
        "--ip-range",
        default="192.168.178.0/24",
        type=_cidr,
        help="CIDR notation for ARP discovery (e.g., 192.168.56.0/24)",
    )
    arp_parser = sub.add_parser(
        "arp-demo",
        help="Demonstrate ARP poisoning in a lab",
        description="Bidirectionally poison two targets' ARP caches and forward their traffic through the attacker.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    arp_parser.add_argument("target1", help="First target IP address (victim A)")
    arp_parser.add_argument("target2", help="Second target IP address (victim B)")
    arp_parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=3,
        help="Number of poison packets to send to each target before looping",
    )
    arp_parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=2.0,
        help="Seconds between poison packet pairs while running",
    )
    arp_parser.add_argument(
        "-I",
        "--iface",
        help="Interface to use for poisoning (controls source MAC). Default: best route or SCAPY_IFACE.",
    )
    dns_parser = sub.add_parser(
        "dns-demo",
        help="Demonstrate DNS spoofing in a lab",
        description="Sniff DNS queries and spoof responses for a target domain, optionally limited to one victim IP.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    dns_parser.add_argument(
        "target",
        help="Domain to spoof (e.g., example.com)",
    )
    dns_parser.add_argument(
        "-s",
        "--spoof-ip",
        help="IP address to return in spoofed answers (default: attacker IP on chosen interface).",
    )
    dns_parser.add_argument(
        "-v",
        "--victim-ip",
        help="Only spoof queries originating from this victim IP (optional).",
    )
    dns_parser.add_argument(
        "-I",
        "--iface",
        help="Interface to sniff on and send spoofed responses from. Default: best route or SCAPY_IFACE.",
    )
    ssl_parser = sub.add_parser(
        "ssl-strip",
        help="Run an HTTPS redirector to strip SSL for a target site",
        description="Bind to 443 with a self-signed cert and 301 redirect inbound HTTPS to HTTP for a given host.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ssl_parser.add_argument(
        "target",
        help="Domain to redirect HTTPS requests toward over HTTP (e.g., demo.local).",
    )
    ssl_parser.add_argument(
        "-b",
        "--bind-ip",
        help="IP address to bind the HTTPS listener to (default: IP of chosen interface).",
    )
    ssl_parser.add_argument(
        "-I",
        "--iface",
        help="Interface used to derive bind IP when --bind-ip is not provided. Default: SCAPY_IFACE or conf.iface.",
    )

    args = parser.parse_args()

    if args.cmd == "discover":
        network_discovery.run(ip_range=args.ip_range)
    elif args.cmd == "arp-demo":
        arp_lab.run(
            target1_ip=args.target1,
            target2_ip=args.target2,
            count=args.count,
            interval=args.interval,
            iface=args.iface,
        )
    elif args.cmd == "dns-demo":
        dns_lab.run(
            target_domain=args.target,
            spoof_ip=args.spoof_ip,
            victim_ip=args.victim_ip,
            iface=args.iface,
        )
    elif args.cmd == "ssl-strip":
        ssl_strip.run(
            site_to_spoof=args.target,
            bind_ip=args.bind_ip,
            iface=args.iface,
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
