import argparse
import re
from tool import network_discovery, arp_lab, dns_lab, analysis, defense_demo


def _cidr(arg_value: str) -> str:
    pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)/(3[0-2]|[12]?\\d)$"
    )
    if not pattern.match(arg_value):
        raise argparse.ArgumentTypeError("IP range must be in CIDR form like 192.168.1.0/24")
    return arg_value

def main():
    parser = argparse.ArgumentParser(
        description="Educational ARP & DNS Manipulation Lab Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
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
    sub.add_parser("arp-demo", help="Demonstrate ARP poisoning in a lab")
    sub.add_parser("dns-demo", help="Demonstrate DNS spoofing in a lab")
    sub.add_parser("analyze", help="Analyze captured ARP/DNS traffic")
    sub.add_parser("defense", help="Show mitigation examples and defenses")

    args = parser.parse_args()

    if args.cmd == "discover":
        network_discovery.run(ip_range=args.ip_range)
    elif args.cmd == "arp-demo":
        arp_lab.run()
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
