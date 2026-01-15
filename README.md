# Educational ARP & DNS Manipulation Tool

This project provides a controlled environment to study ARP and DNS weaknesses inside an **authorized lab network** (e.g., host-only or isolated NAT). It is for **education only**.

Implemented demos:
- `discover` — ARP network discovery
- `arp-demo` — ARP MITM between a victim and router
- `dns-demo` — DNS spoofing for a target domain
- `ssl-strip` — HTTPS listener that redirects or serves custom HTML

---

## Requirements

- Kali Linux recommended (other Linux may work)
- Python 3.8+
- System packages (Kali):
  ```
  sudo apt update && sudo apt upgrade -y
  sudo apt install -y python3 python3-pip python3-venv tcpdump libpcap-dev
  ```
- Python deps:
  ```
  pip install scapy
  ```

---

## Installation

```bash
cd educational_arp_dns_tool
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install scapy
```

---

## Running the CLI

Run with sudo/root for packet features:

```bash
sudo python3 -m tool.cli --help
```

Interactive mode (no args) shows a numbered menu and prompts for fields:

```bash
sudo python3 -m tool.cli
```

Subcommands:
```
discover   # ARP sweep of a CIDR
arp-demo   # ARP MITM between victim and router
dns-demo   # DNS spoof a target domain
ssl-strip  # HTTPS redirector or custom HTML
```

Default interface is `eth0` for demos that send/receive packets; override with `-I`.

---

## How Each Demo Works

### ARP Lab (`arp-demo`)
This module performs a classic MITM between a victim and a router/gateway:
- Resolves the victim and router MAC addresses using ARP.
- Sends spoofed ARP replies so both endpoints map the other IP to the attacker MAC.
- Forwards Ethernet frames between victim and router so connectivity continues while traffic passes through the attacker.

### DNS Lab (`dns-demo`)
This module spoofs DNS answers for a target domain:
- Sniffs UDP/53 DNS queries on the chosen interface.
- Matches queries for the target domain (optionally only from one victim IP).
- Sends a forged DNS response pointing to the spoof IP.
- If a victim IP is provided, inserts an iptables rule to drop that victim's real DNS replies so spoofing wins the race.

### SSL Strip (`ssl-strip`)
This module terminates HTTPS locally and responds in one of two modes:
- Redirect mode: sends a 301 to `http://<target-host>`.
- HTML mode: serves custom HTML from `--html` or `--html-file`.

It does not reroute traffic by itself; you must direct the victim to the attacker (hosts file, DNS spoof, or MITM routing). HSTS-preloaded sites will not downgrade.

---

## Examples

### Discover
```bash
sudo python3 -m tool.cli discover -r 192.168.178.0/24
```

### ARP poisoning demo
```bash
sudo python3 -m tool.cli arp-demo 192.168.178.10 192.168.178.1 -I eth0 -c 5 -i 1
```
- `-I` interface; `-c` initial poison bursts; `-i` interval while running.

### DNS spoofing demo
```bash
sudo python3 -m tool.cli dns-demo example.com -s 192.168.178.76 -I eth0
```
- Add `-v <victim-ip>` to only spoof one host.

### SSL strip demo (lab hostname)
```bash
# attacker terminal 1: plain HTTP target
sudo python3 -m http.server 80

# attacker terminal 2: SSL redirector (301 to HTTP)
sudo python -m tool.cli ssl-strip demo.local -b 192.168.178.76 -I eth0

# victim: map hostname to attacker IP
echo "192.168.178.76 demo.local" | sudo tee -a /etc/hosts
```
Browse to `https://demo.local` from the victim, accept the cert warning, and you should be redirected to `http://demo.local`. HSTS-preloaded sites (e.g., google.com, example.com) will not downgrade.

### SSL strip demo (custom HTML)
```bash
sudo python -m tool.cli ssl-strip demo.local -b 192.168.178.76 -I eth0 --html "<h1>test passed</h1>"
```

---

## Ethical Notice

Use only on networks you own or where you have explicit written permission. Running ARP/DNS manipulation on unauthorized networks is illegal and unethical. This project exists for educational purposes aligned with defensive security learning.
