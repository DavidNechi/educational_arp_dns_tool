import argparse
from tool import network_discovery, arp_lab, dns_lab, analysis, defense_demo

def main():
    parser = argparse.ArgumentParser(
        description="Educational ARP & DNS Manipulation Lab Tool"
    )

    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("discover")
    sub.add_parser("arp-demo")
    sub.add_parser("dns-demo")
    sub.add_parser("analyze")
    sub.add_parser("defense")

    args = parser.parse_args()

    if args.cmd == "discover":
        network_discovery.run()
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
