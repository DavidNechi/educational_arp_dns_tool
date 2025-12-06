# Educational ARP & DNS Manipulation Tool

This project provides a controlled environment to study and demonstrate ARP and DNS behavior, including their weaknesses, inside an **authorized lab network** (e.g., VirtualBox host-only network).
It is designed for **education only**, following responsible and ethical security practices.

Only the **network discovery module** is fully implemented at this stage.
Other modules (ARP poisoning demo, DNS spoofing demo, defense mechanisms) will be implemented later.

---

## Requirements

### Operating System

* Kali Linux (recommended)
* Other Linux distributions may also work

### Python

* Python **3.8+**

### System Packages (Kali Linux)

Install required system components:

```
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv
sudo apt install -y tcpdump libpcap-dev
```

### Python Dependencies

The tool currently requires:

* Scapy

Install it inside your virtual environment (see below):

```
pip install scapy
```

---

## Installation

Open a terminal and navigate into the project folder:

```
cd educational_arp_dns_tool
```

Create a virtual environment:

```
python3 -m venv .venv
```

Activate it:

* Linux/macOS:

  ```
  source .venv/bin/activate
  ```

Upgrade pip and install dependencies:

```
pip install --upgrade pip
pip install scapy
```

If this fails, simply run the application with `sudo`.

---

## Running the Application

The entry point of the tool is the CLI:

```
python3 -m tool.cli --help
```

You should see available subcommands:

```
discover     # ARP-based network discovery (currently working)
arp-demo     # placeholder
dns-demo     # placeholder
analyze      # placeholder
defense      # placeholder
```

Because ARP and packet-level operations require elevated privileges, run the tool with `sudo` on Kali.

---

## Network Discovery (Current Working Scenario)

To run the ARP-based host discovery:

```
sudo python3 -m tool.cli discover
```

This performs:

1. ARP broadcast scanning across the configured subnet
2. Collection of responses
3. Output of discovered IP/MAC pairs

Example output:

```
[i] Starting ARP scan on range: 192.168.56.0/24
[i] ARP scan finished, found 2 hosts.

[*] Discovered hosts:
    192.168.56.1      08:00:27:11:22:33
    192.168.56.10     08:00:27:aa:bb:cc
```

If no hosts are found:

* Check the subnet configured in `network_discovery.run()`
* Ensure other machines are running on the same host-only network
* Confirm you are in a safe, isolated lab environment

---

## Ethical Notice

This tool must be used **only**:

* In private networks you own, or
* In networks where you have **explicit written permission**

Running ARP/DNS manipulation on unauthorized networks is illegal and unethical.

This project exists for **educational purposes** aligned with defensive security learning.

---

## Summary of Commands

```
cd educational_arp_dns_tool
python3 -m venv .venv
source .venv/bin/activate
pip install scapy
sudo python3 -m tool.cli discover
```

