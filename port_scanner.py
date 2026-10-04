#!/usr/bin/env python3
"""
Port Scanner
------------
A multithreaded TCP port scanner with banner grabbing.
Built for learning network fundamentals and reconnaissance basics.

⚠️  Only scan systems you own or have explicit permission to test.

Usage:
    python port_scanner.py <target> [-p START-END] [-t THREADS] [--banner]
Example:
    python port_scanner.py 127.0.0.1 -p 1-1024 -t 100 --banner
"""

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Well-known port -> service hints
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt",
}


def grab_banner(sock: socket.socket) -> str:
    """Try to read a service banner from an open socket."""
    try:
        sock.settimeout(1.5)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner.split("\n")[0][:60] if banner else ""
    except Exception:
        return ""


def scan_port(target: str, port: int, grab: bool) -> tuple | None:
    """Attempt a TCP connection; return (port, service, banner) if open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        if sock.connect_ex((target, port)) == 0:
            service = COMMON_PORTS.get(port, "unknown")
            banner = grab_banner(sock) if grab else ""
            return (port, service, banner)
    except Exception:
        pass
    finally:
        sock.close()
    return None


def main():
    parser = argparse.ArgumentParser(description="Multithreaded TCP port scanner")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range, e.g. 1-1024 (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("--banner", action="store_true",
                        help="Grab service banners from open ports")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"❌ Could not resolve hostname: {args.target}")
        return

    try:
        start, end = map(int, args.ports.split("-"))
    except ValueError:
        print("❌ Invalid port range. Use format START-END, e.g. 1-1024")
        return

    print(f"🔍 Scanning {args.target} ({target_ip}), ports {start}-{end}")
    print(f"⏱️  Started at {datetime.now().strftime('%H:%M:%S')}\n")

    open_ports = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [pool.submit(scan_port, target_ip, p, args.banner)
                   for p in range(start, end + 1)]
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)
                port, service, banner = result
                line = f"  ✅ Port {port:<6} OPEN   ({service})"
                if banner:
                    line += f"  — {banner}"
                print(line)

    print(f"\n🏁 Done. {len(open_ports)} open port(s) found.")


if __name__ == "__main__":
    main()
