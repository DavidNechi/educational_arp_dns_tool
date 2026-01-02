# DNS LAB DOCUMENTATION – EDUCATIONAL DNS SPOOFING

1. Purpose of the DNS Lab
- The purpose of this lab is to demonstrate how DNS spoofing can be performed in a controlled and authorized environment, and to understand why such an attack depends on lower network layers.

- The lab shows that DNS spoofing is not a standalone attack. It only works if the attacker is able to see the victim’s DNS queries. To achieve this, the attacker must first place themselves in a Man-in-the-Middle (MITM) position using ARP spoofing.

- The attacker machine is a Kali Linux virtual machine, and the victim is a macOS machine on the same local network. All testing was done on a private network owned by the experimenter.

2. Why ARP Spoofing Is Required
- On a normal switched network, devices do not see each other’s unicast traffic. DNS queries sent by the victim go directly to the router and are not visible to other hosts.

DNS spoofing requires:
    1. the DNS transaction ID
    2. the UDP source port
    3. the destination DNS server

- These values are only visible if the attacker can observe the DNS query. ARP spoofing is used to redirect the victim’s traffic through the attacker, making this observation possible.

- Without ARP spoofing, DNS spoofing cannot work.

3. Starting the ARP Spoofing (MITM Setup)
- On the attacker (Kali Linux), ARP spoofing is started using the ARP lab module:

Command:

`sudo python -m tool.cli arp-demo`


What this command does:
- Continuously sends forged ARP replies to the victim
- Associates the gateway IP address with the attacker’s MAC address
- Forces all IPv4 traffic from the victim to pass through the attacker
- This process must run continuously because ARP entries expire and can be overwritten by legitimate ARP traffic.

4. Verifying That Traffic Passes Through the Attacker
- Before attempting DNS spoofing, it is important to confirm that the attacker can see the victim’s DNS traffic.

On the attacker, run:

`sudo tcpdump -n -i eth0 'udp port 53 and host 192.168.1.254'`

What this command does:
- Listens for DNS traffic over UDP port 53
- Filters packets to only those involving the victim
- Disables name resolution for clarity

On the victim, generate a DNS query using classic DNS over IPv4 (macOS):

`dig google.com @8.8.8.8`


Why this command is important:
- Forces DNS over UDP port 53
- Forces IPv4 (required for ARP-based attacks)
- Avoids DNS over HTTPS and IPv6
- If the DNS query appears in the tcpdump output on the attacker, the MITM position is correctly established.

5. Running the DNS Spoofing Module

Once traffic visibility is confirmed, the DNS spoofing module is started on the attacker:

Command:

`sudo python -m tool.cli dns-demo`


What the DNS spoofing module does:
- Listens for DNS queries on UDP port 53
- Logs all observed DNS queries for visibility
- Checks each query against a strict whitelist of lab-only domains
- Crafts and sends forged DNS responses only for whitelisted domains
- The whitelist ensures that the attack is limited to test domains and cannot affect real services.

Triggering the DNS Spoofing Attack
- On the victim machine, query a whitelisted domain:

Command:

`dig lab-victim.test @8.8.8.8 -4`


Expected output on the attacker:

[DNS] Query for lab-victim.test
   [+] Spoofing -> 10.0.0.66


This shows that:
- The attacker observed the DNS query
- The domain matched the whitelist
- A forged DNS response was constructed and sent

Expected output on the victim:

lab-victim.test.   30   IN   A   10.0.0.66


- This confirms that the victim accepted the attacker-controlled DNS response, demonstrating a loss of DNS integrity.

6. What the Attack Actually Did
When the victim requested the IP address of a domain, the attacker:
- Observed the DNS query in transit
- Copied the transaction ID and UDP ports
- Created a forged DNS response containing a fake IP address
- Sent the forged response before the legitimate DNS server replied
- Because classic DNS does not authenticate responses, the victim accepted the forged answer.

7. Cleanup and Restoration
- After the experiment, normal network operation must be restored.

On the attacker:
- Stop the DNS spoofing module
- Stop the ARP spoofing module
- Restore correct ARP mappings
- On the victim (macOS), flush the DNS cache:

`sudo dscacheutil -flushcache`
`sudo killall -HUP mDNSResponder`


After cleanup, querying the test domain again should no longer return the spoofed IP address.

8. Summary

This DNS lab demonstrates that DNS spoofing depends on both protocol weaknesses and network positioning. By combining ARP spoofing with forged DNS responses, an attacker can manipulate name resolution in a local network. At the same time, the lab shows why modern security mechanisms are effective at preventing such attacks in practice.