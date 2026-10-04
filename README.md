# 🔍 Port Scanner

A multithreaded TCP port scanner written in Python, with service detection and banner grabbing. Built to learn networking fundamentals and reconnaissance techniques used in cybersecurity.

> ⚠️ **Disclaimer:** Only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal.

## Features

- Fast multithreaded scanning (configurable thread count)
- Custom port ranges
- Service name hints for well-known ports
- Optional banner grabbing to identify running services

## Usage

```bash
# Scan the 1024 most common ports on localhost
python port_scanner.py 127.0.0.1

# Custom range with banner grabbing
python port_scanner.py 127.0.0.1 -p 1-5000 -t 200 --banner
```

Example output:

```
🔍 Scanning 127.0.0.1 (127.0.0.1), ports 1-1024
⏱️  Started at 14:32:10

  ✅ Port 22     OPEN   (SSH)
  ✅ Port 80     OPEN   (HTTP)  — Apache/2.4.52

🏁 Done. 2 open port(s) found.
```

## What I learned

- TCP sockets and the connect-scan technique
- Multithreading with `ThreadPoolExecutor`
- Banner grabbing for service fingerprinting
- CLI design with `argparse`

## Tech

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
