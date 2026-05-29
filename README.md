# NetGhost

**Real-time network security analysis in your terminal. Lightweight, cross-platform, dockerized.**

NetGhost is a terminal user interface (TUI) tool for live packet capture, traffic analysis, and connection interception. It sits between Wireshark's complexity and simple CLI tools — a cyberpunk-styled dashboard where you can monitor traffic at a glance, filter by protocol, record to PCAP, and defend against unwanted connections with a single keypress.

---

## Features

- **Live Traffic Table** — real-time packet display with protocol-colored rows, newest first
- **Dashboard Panel** — packet count, data volume, rate, bandwidth, active connections, uptime
- **Protocol Filters** — 10 one-click filter buttons (ALL, TCP, UDP, DNS, HTTP, HTTPS, ICMP, ARP, SSH, DHCP)
- **Active Connections Panel** — aggregated flows with byte counters
- **PCAP Recording** — `S` key to start/stop saving packets to file
- **Defensive TCP Reset** — `R` key sends RST to terminate a selected TCP connection
- **IP Blocking** — `B` key to block a selected source IP
- **Play/Pause** — `Space` or click button to freeze live traffic for free scrolling
- **Bilingual UI** — `L` key toggles between English and Turkish
- **Dark Cyberpunk Theme** — neon cyan, green, magenta on deep black
- **Test / Demo Mode** — `NETGHOST_DEV=1` simulates traffic — no root needed

---

## Quick Start

### Docker (Recommended)

```bash
# Clone
git clone https://github.com/labirend/NetGhost.git
cd NetGhost

# Build
docker compose build

# Run (real capture — needs NET_RAW + NET_ADMIN)
docker compose run netghost

# Run in demo mode (no privileges required)
NETGHOST_DEV=1 docker compose run netghost
```

The `docker-compose.yml` grants only the minimum capabilities:
- `NET_RAW` — raw socket access (packet capture)
- `NET_ADMIN` — network administration (IP blocking / RST)

### Natively (Linux)

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
NETGHOST_DEV=1 python -m netghost
```

> **Note:** Real packet capture requires root or `CAP_NET_RAW` / `CAP_NET_ADMIN`. The Docker setup handles this. Without these, the tool falls back to demo mode automatically.

---

## Keybindings

| Key     | Action                                |
|---------|---------------------------------------|
| `S`     | Start / Stop PCAP recording           |
| `R`     | Send TCP RST to selected connection   |
| `B`     | Block source IP of selected packet    |
| `Space` | Pause / Resume live traffic           |
| `L`     | Toggle language (EN ↔ TR)             |
| `Q`     | Quit                                  |

---

## Interface Layout

```
┌───────────────────────────────────────────────────────────────┐
│  ⛨ NetGhost v0.1.0    [eth0]    IP:192.168.1.100 │ MAC:00:1a │
├──────────────┬────────────────────────────────────────────────┤
│  DASHBOARD   │  TRAFFIC TABLE                                 │
│  Packets:287 │  Proto  Src IP         Dst IP          Size    │
│  Data: 142KB │  TCP    10.0.0.5:443   192.168.1.100  1280    │
│  Rate: 34/s  │  DNS    8.8.8.8:53     10.0.0.5:49231  89     │
│  Bw:   1.2M  │  HTTPS  142.250.80.46  192.168.1.100  1460    │
│  Conn:  12   │  ...                                          │
│  Up:   00:34 │                                                │
│              │  CONNECTIONS PANEL                             │
│  FILTERS     │  Src            Dst            Proto  Bytes    │
│  [ALL] TCP   │  10.0.0.5      192.168.1.100  TCP    14.2K    │
│  UDP  DNS    │  8.8.8.8       10.0.0.5       DNS    2.1K     │
│  HTTP HTTPS  │  192.168.1.100 255.255.255.0  DHCP   1.4K     │
│  ICMP ARP    │                                                │
│  SSH  DHCP   │                                                │
│              │                                                │
│  [■ STOP]    │                                                │
├──────────────┴────────────────────────────────────────────────┤
│  S:Record  R:Reset  B:Block  Space:Pause  L:EN/TR  Q:Quit   │
└───────────────────────────────────────────────────────────────┘
```

---

## Architecture

```
NetGhost/
├── Dockerfile              # Multi-stage build (python:3.11-slim)
├── docker-compose.yml      # Host networking, minimum caps
├── pyproject.toml          # Package metadata
├── requirements.txt        # textual, scapy, rich
├── setup.py                # Setuptools shim
├── .dockerignore
├── .gitignore
├── README.md
├── LICENSE                 # MIT
├── tests/                  # Diagnostic test scripts
└── netghost/
    ├── __init__.py
    ├── __main__.py          # `python -m netghost` entry
    ├── app.py               # Textual App — compose → push_screen
    ├── i18n.py              # Bilingual translation engine
    ├── locales/
    │   ├── en.json          # 50+ English UI strings
    │   └── tr.json          # Turkish translations
    ├── capture/
    │   ├── engine.py        # AsyncSniffer (Scapy) + interface info
    │   ├── parser.py        # L2/L3/L4 packet parser
    │   ├── interceptor.py   # RST injection + iptables blocking
    │   └── recorder.py      # PCAP file writer
    ├── models/
    │   └── packet.py        # PacketInfo dataclass
    ├── ui/
    │   ├── css/
    │   │   └── cyberpunk.tcss   # Full theme stylesheet
    │   ├── screens/
    │   │   └── main_screen.py   # 4-zone layout, all button handlers
    │   └── widgets/
    │       ├── interface_bar.py # Shield logo, IP/MAC, recording indicator
    │       ├── dashboard.py     # 6-row summary panel
    │       ├── traffic_table.py # Newest-first deque, colored rows, filtering
    │       └── connection_panel.py  # Aggregated flow view
    └── utils/
        └── network.py      # Interface discovery helpers
```

---

## Docker on Linux

```bash
# Build
docker compose build

# Run with host networking (full interface visibility)
docker compose run netghost

# Demo mode (no root, simulated traffic)
NETGHOST_DEV=1 docker compose run netghost
```

> **Note:** Linux users must have Docker installed and their user in the `docker` group. If you get a permission error, run `newgrp docker` and try again.

---

## Docker on macOS & Windows

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/), then the same commands work:

```bash
docker compose build
docker compose run netghost
```

Docker Desktop runs a Linux VM under the hood — the container is Linux on all platforms.

---

## Manual PCAP Recording

Press `S` to begin recording. Press `S` again to stop. The file is saved to the container's working directory as `netghost_YYYYMMDD_HHMMSS.pcap`.

---

## Development

```bash
git clone https://github.com/labirend/NetGhost.git
cd NetGhost
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Demo mode (no root)
NETGHOST_DEV=1 python -m netghost
```

### Existing branch testing directory

A fully tested copy of the codebase lives in `NetGhost-main-github/` alongside the root. This directory is gitignored and can be used for iterative experimentation without disturbing the main source tree.

---

## Roadmap

- [ ] Runtime interface switching
- [ ] BPF filter expressions (text-based filtering)
- [ ] Bandwidth timeline chart
- [ ] GeoIP enrichment
- [ ] Custom rule engine (alert on suspicious patterns)
- [ ] Theme variants

---

## License

MIT
