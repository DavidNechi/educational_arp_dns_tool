# Lab Guide – Using the Current Tool Version

This guide explains how to use the current version of the project from Visual Studio Code:

- Project structure is created.
- `cli.py` is wired as the entry point.
- `network_discovery.py` can do a simple ARP-based host scan on a lab network.

The goal is to be able to:
1. Open the project in VS Code.
2. Set up Python and Scapy.
3. Run the CLI and use the `discover` scenario to list hosts on the lab network.

---

## 1. Open the project in VS Code

1. Start Visual Studio Code.
2. Click **File → Open Folder...**.
3. Select the project root folder `educational_arp_dns_tool/`.
4. You should see at least:
   - `tool/` (contains `cli.py`, `network_discovery.py`, etc.)
   - `docs/`
   - `README.md`

---

## 2. Set up a Python virtual environment

From VS Code, open a terminal (**View → Terminal**) and run:

```bash
cd educational_arp_dns_tool

# Create a virtual environment (one-time setup)
python3 -m venv .venv

# Activate the virtual environment
# Linux / macOS:
source .venv/bin/activate

# Windows (PowerShell):
# .venv\Scripts\Activate.ps1
