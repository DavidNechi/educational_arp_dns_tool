# DNS Lab (Attack and Defense)

## Goal

Demonstrate DNS spoofing by forging replies to a victim's DNS queries in a controlled lab.

## How the DNS Lab Works

Inputs:
- Target domain (e.g., `example.com`)
- Optional spoof IP (defaults to attacker interface IP)
- Optional victim IP filter (`-v`)
- Interface (`-I`, default `eth0`)

Flow:
1. The attacker listens for UDP/53 DNS queries on the chosen interface.
2. When a query matches the target domain, it crafts a DNS response with the same transaction ID and ports.
3. The forged response points to the spoof IP and is sent back to the victim.
4. If a victim IP is provided, the tool inserts an iptables rule to drop that victim's real DNS replies so the spoof wins the race.

Note: The attacker must be able to see the victim's DNS traffic. This usually requires a MITM position (e.g., `arp-demo`), or a shared network where queries are visible.

## Running the Demo

Command-line mode:
```bash
sudo python3 -m tool.cli dns-demo example.com -s 192.168.178.76 -v 192.168.178.10 -I eth0
```

Interactive mode:
```bash
sudo python3 -m tool.cli
```
Then pick `dns-demo` from the menu and enter the fields.

## Defensive Measures

- Use DNSSEC-validating resolvers when possible.
- Prefer DoT/DoH from clients to prevent in-path spoofing.
- Monitor DNS traffic for unexpected changes in A/AAAA responses.
- Limit MITM opportunities with network segmentation and ARP protections.
