import argparse
import ipaddress
from tool import network_discovery, arp_lab, dns_lab, analysis, defense_demo


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
        description="Educational ARP & DNS Manipulation Lab Tool",
        formatter_class=_HelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m tool.cli discover -r 192.168.178.0/24\n"
            "  python -m tool.cli arp-demo 192.168.178.1 192.168.178.63 -I eth0 -c 5 -i 1\n"
            "  python -m tool.cli dns-demo"
        ),
    )

    sub = parser.add_subparsers(dest="cmd")

    discover_parser = sub.add_parser(
        "discover",
        help="ARP scan a subnet (use -r/--ip-range to set CIDR)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    discover_parser.add_argument(
        "-r",
        "--ip-range",
        default="192.168.178.0/24",
        type=_cidr,
        help="CIDR notation for ARP discovery (default: 192.168.178.0/24)",
    )
    arp_parser = sub.add_parser(
        "arp-demo",
        help="Demonstrate ARP poisoning in a lab",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    arp_parser.add_argument("target1", help="First target IP address")
    arp_parser.add_argument("target2", help="Second target IP address")
    arp_parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=3,
        help="Number of poison packets to send to each target",
    )
    arp_parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=2.0,
        help="Seconds between poison packet pairs",
    )
    arp_parser.add_argument(
        "-I",
        "--iface",
        help="Interface to use for poisoning (controls source MAC)",
    )
    sub.add_parser("dns-demo", help="Demonstrate DNS spoofing in a lab")
    sub.add_parser("analyze", help="Analyze captured ARP/DNS traffic")
    sub.add_parser("defense", help="Show mitigation examples and defenses")

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
        dns_lab.run()
    elif args.cmd == "analyze":
        analysis.run()
    elif args.cmd == "defense":
        defense_demo.run()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
