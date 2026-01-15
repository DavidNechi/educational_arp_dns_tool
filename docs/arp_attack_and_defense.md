# ARP Lab (Attack and Defense)

## Goal

Demonstrate how ARP cache poisoning can place an attacker in the middle of traffic between a victim and a router, and how to recognize/defend against it.

## How the ARP Lab Works

Inputs:
- Victim IP
- Router/gateway IP
- Interface (`-I`, default `eth0`)
- Optional: poison count (`-c`) and interval (`-i`)

Flow:
1. The attacker resolves the victim and router MAC addresses using ARP.
2. It sends spoofed ARP replies so the victim believes the router IP is at the attacker MAC, and the router believes the victim IP is at the attacker MAC.
3. The tool forwards Ethernet frames between victim and router so connectivity continues while traffic passes through the attacker.

## Running the Demo

Command-line mode:
```bash
sudo python3 -m tool.cli arp-demo <victim-ip> <router-ip> -I eth0 -c 5 -i 1
```

Interactive mode:
```bash
sudo python3 -m tool.cli
```
Then pick `arp-demo` from the menu and enter the victim/router IPs.

## What to Observe

- Victim ARP table shows the router IP mapped to the attacker MAC.
- Router ARP table shows the victim IP mapped to the attacker MAC.
- The attacker sees and forwards traffic between both endpoints.

## Defensive Measures

- Enable DHCP snooping + Dynamic ARP Inspection (DAI) on managed switches.
- Use static ARP entries for critical systems where possible.
- Segment networks (VLANs) to reduce L2 attack surface.
- Monitor ARP tables and alert on rapid MAC/IP changes (arpwatch, IDS).
