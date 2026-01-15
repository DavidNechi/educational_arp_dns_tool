import argparse
import ipaddress
import sys
from typing import Any, Optional, Tuple
from tool import network_discovery, arp_lab, dns_lab, ssl_strip


class _HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    """
    Combine defaults display with nice multiline epilog formatting.
    """
    pass


DEFAULT_IFACE = "eth0"


def _cidr(arg_value: str) -> str:
    try:
        ipaddress.ip_network(arg_value, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError("IP range must be in CIDR form like 192.168.1.0/24")
    return arg_value


def _prompt(
    text: str,
    default: Optional[str] = None,
    allow_empty: bool = False,
    validator=None,
) -> Any:
    while True:
        suffix = f" [{default}]" if default is not None else ""
        try:
            value = input(f"{text}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            if default is None:
                return default
            if validator:
                try:
                    return validator(default)
                except Exception as exc:
                    print(f"[!] {exc}")
                    return None
            return default
        if not value:
            if default is not None:
                if validator:
                    try:
                        return validator(default)
                    except Exception as exc:
                        print(f"[!] {exc}")
                        continue
                return default
            if allow_empty:
                return None
            print("[!] Value required.")
            continue
        if validator:
            try:
                return validator(value)
            except Exception as exc:
                print(f"[!] {exc}")
                continue
        return value


def _to_int(value: str) -> int:
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError("Enter a whole number.") from exc


def _to_float(value: str) -> float:
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError("Enter a number.") from exc


def _validate_cidr(value: str) -> str:
    try:
        return _cidr(value)
    except argparse.ArgumentTypeError as exc:
        raise ValueError(str(exc)) from exc


def _prompt_yes_no(text: str, default: bool = False) -> bool:
    default_value = "y" if default else "n"
    value = _prompt(text, default=default_value, allow_empty=True)
    if value is None:
        return default
    return value.lower() in ("y", "yes")


def _prompt_choice(text: str, options: Tuple[str, ...], default: str) -> str:
    def _validator(value: str) -> str:
        if value not in options:
            raise ValueError(f"Choose one of: {', '.join(options)}")
        return value

    return _prompt(text, default=default, validator=_validator)


def _run_interactive(parser: argparse.ArgumentParser) -> None:
    menu = (
        ("discover", "ARP scan a subnet"),
        ("arp-demo", "ARP MITM between victim and router"),
        ("dns-demo", "DNS spoof a target domain"),
        ("ssl-strip", "HTTPS redirector or HTML response"),
        ("help", "Show CLI help"),
        ("exit", "Exit"),
    )

    while True:
        print("\nInteractive menu:")
        for index, (cmd, desc) in enumerate(menu, start=1):
            print(f"  {index}) {cmd} - {desc}")

        def _menu_choice(value: str) -> int:
            choice = _to_int(value)
            if choice < 1 or choice > len(menu):
                raise ValueError("Select a valid menu index.")
            return choice

        choice = _prompt("Select an option", validator=_menu_choice)
        if choice is None:
            return
        command = menu[choice - 1][0]

        if command == "exit":
            return
        if command == "help":
            parser.print_help()
            continue

        if command == "discover":
            ip_range = _prompt("IP range (CIDR)", default="192.168.178.0/24", validator=_validate_cidr)
            if not ip_range:
                return
            network_discovery.run(ip_range=ip_range)
        elif command == "arp-demo":
            target1 = _prompt("Victim IP")
            target2 = _prompt("Router/Gateway IP")
            if not target1 or not target2:
                return
            count = _prompt("Poison count", default="3", validator=_to_int)
            interval = _prompt("Interval seconds", default="2.0", validator=_to_float)
            iface = _prompt("Interface", default=DEFAULT_IFACE)
            arp_lab.run(
                victim_ip=target1,
                router_ip=target2,
                count=count,
                interval=interval,
                iface=iface,
            )
        elif command == "dns-demo":
            target = _prompt("Target domain (e.g., example.com)")
            if not target:
                return
            spoof_ip = _prompt("Spoof IP (blank for interface IP)", allow_empty=True)
            victim_ip = _prompt("Victim IP (blank for any)", allow_empty=True)
            iface = _prompt("Interface", default=DEFAULT_IFACE)
            dns_lab.run(
                target_domain=target,
                spoof_ip=spoof_ip,
                victim_ip=victim_ip,
                iface=iface,
            )
        elif command == "ssl-strip":
            target = _prompt("Target domain (e.g., demo.local)")
            if not target:
                return
            bind_ip = _prompt("Bind IP (blank for interface IP)", allow_empty=True)
            iface = _prompt("Interface", default=DEFAULT_IFACE)
            html_body = None
            html_file = None
            if _prompt_yes_no("Serve custom HTML instead of redirect? (y/N)", default=False):
                source = _prompt_choice("HTML source: 1) inline 2) file", options=("1", "2"), default="1")
                if source == "2":
                    html_file = _prompt("HTML file path")
                else:
                    html_body = _prompt("HTML (single line)", default="<h1>test passed</h1>")
            ssl_strip.run(
                site_to_spoof=target,
                bind_ip=bind_ip,
                iface=iface,
                html_body=html_body,
                html_file=html_file,
            )

        again = _prompt_yes_no("Run another command? (y/N)", default=False)
        if not again:
            return


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
        description="Poison a victim and a router/gateway to forward their traffic through the attacker (MITM).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    arp_parser.add_argument("victim", help="Victim IP address")
    arp_parser.add_argument("router", help="Router/Gateway IP address")
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
        default=DEFAULT_IFACE,
        help="Interface to use for poisoning (controls source MAC).",
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
        default=DEFAULT_IFACE,
        help="Interface to sniff on and send spoofed responses from.",
    )
    ssl_parser = sub.add_parser(
        "ssl-strip",
        help="Run an HTTPS redirector to strip SSL for a target site",
        description=(
            "Bind to 443 with a self-signed cert and 301 redirect inbound HTTPS to HTTP for a given host, "
            "or serve custom HTML instead of redirecting."
        ),
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
        default=DEFAULT_IFACE,
        help="Interface used to derive bind IP when --bind-ip is not provided.",
    )
    html_group = ssl_parser.add_mutually_exclusive_group()
    html_group.add_argument(
        "--html",
        help="Inline HTML to serve instead of redirecting (wraps plain text in a minimal page).",
    )
    html_group.add_argument(
        "--html-file",
        help="Path to an HTML file to serve instead of redirecting.",
    )

    if len(sys.argv) == 1:
        _run_interactive(parser)
        return

    args = parser.parse_args()

    if args.cmd == "discover":
        network_discovery.run(ip_range=args.ip_range)
    elif args.cmd == "arp-demo":
        arp_lab.run(
            victim_ip=args.victim,
            router_ip=args.router,
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
            html_body=args.html,
            html_file=args.html_file,
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
