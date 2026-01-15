# Overview

This project is an educational lab for ARP and DNS behavior in an authorized network. Each scenario is implemented as a small module in `tool/` and exposed through a single CLI.

## Modules

- `discover`: ARP sweep of a CIDR to list IP/MAC pairs.
- `arp-demo`: MITM between a victim and router using ARP poisoning and L2 forwarding.
- `dns-demo`: Spoof DNS answers for a target domain.
- `ssl-strip`: HTTPS listener that redirects to HTTP or serves custom HTML.

## Quick Start

- Interactive menu: `sudo python3 -m tool.cli`
- Help/flags: `sudo python3 -m tool.cli --help`

Default interface is `eth0` for demos that send/receive packets. Override with `-I` where supported.

## Typical Lab Flow

1. Run `discover` to identify the victim and router IPs.
2. Run `arp-demo` to place the attacker in the traffic path.
3. Run `dns-demo` or `ssl-strip` to demonstrate higher-level manipulation.
