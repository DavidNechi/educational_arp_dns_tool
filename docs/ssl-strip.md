# SSL Strip Lab

## Goal

Demonstrate how an HTTPS connection can be terminated by an attacker in a lab environment and either redirected to HTTP or served a custom HTML response.

## Inputs

- Target host (e.g., `demo.local`)
- Optional: bind IP (`-b`, defaults to interface IP)
- Interface (`-I`, default `eth0`)
- Optional: `--html` or `--html-file` to serve custom HTML

## How It Works

1. The tool binds to TCP/443 and generates a short-lived self-signed certificate if needed.
2. When a client connects:
   - Redirect mode: responds with `301 Location: http://<target-host>`.
   - HTML mode: responds with a 200 and the provided HTML body.
3. The tool does not redirect traffic by itself. You must point the victim to the attacker
   (hosts file, DNS spoofing, or MITM routing).

## Running the Demo

Redirect mode:
```bash
sudo python3 -m tool.cli ssl-strip demo.local -b 192.168.178.76 -I eth0
```

Custom HTML mode:
```bash
sudo python3 -m tool.cli ssl-strip demo.local -b 192.168.178.76 -I eth0 --html "<h1>test passed</h1>"
```

## Minimal Lab Setup (Two VMs)

Attacker VM:
```bash
sudo python3 -m http.server 80
sudo python3 -m tool.cli ssl-strip demo.local -b 192.168.178.76 -I eth0
```

Victim VM:
```bash
echo "192.168.178.76 demo.local" | sudo tee -a /etc/hosts
```

Then browse to `https://demo.local` on the victim and accept the certificate warning.

## Troubleshooting

- If the browser connects to the real site, the victim is not resolving to the attacker IP.
- If you see “Unable to connect,” the attacker is not listening on 443 or the wrong IP.
- HSTS-preloaded domains (e.g., google.com, example.com) will not downgrade to HTTP.

## Defensive Notes

- HSTS prevents HTTPS downgrade attacks.
- Use valid TLS certificates and prefer HTTPS everywhere.
- DNSSEC/DoH reduces DNS tampering risk in-path.
