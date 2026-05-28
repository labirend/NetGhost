# NetGhost

**Real-time network security analysis in your terminal. Lightweight, cross-platform, and layer-expandable.**

NetGhost is a terminal user interface (TUI) tool for live packet capture, traffic analysis, and connection interception. Designed to bridge the gap between Wireshark's complexity and simple CLI tools, NetGhost offers a clean, cyberpunk-styled interface where beginners can monitor traffic at a glance while experts can drill down into packet details—layer by layer.

---

## Features

- **Live Traffic Table** — real-time display of captured packets with protocol-colored rows
- **Layered Packet Inspection** — expand any packet to inspect Ethernet (L2), IP (L3), TCP/UDP (L4), and payload
- **Active Connections Panel** — aggregated flow view with byte counters
- **Real-time Statistics** — packet rate, bandwidth, active connections, uptime
- **PCAP Recording** — press `S` to start/stop saving captured packets to a `.pcap` file
- **Connection Interception** — send RST to terminate TCP connections (`R`), block source IPs (`B`)
- **Bilingual Interface** — toggle between English and Turkish on the fly (`L`)
- **Dark Cyberpunk Theme** — neon cyan, green, magenta on deep black background
- **Test / Demo Mode** — no network privileges? Built-in simulated traffic for evaluation

---

## Quick Start

### Prerequisites

- **Docker** (recommended) — works on Linux, macOS, and Windows via Docker Desktop
- Or **Python 3.11+** with pip for native execution

### Run with Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/labirend/NetGhost.git
cd NetGhost

# Build the image
docker compose build

# Run (requires NET_RAW + NET_ADMIN for packet capture)
docker compose run netghost

# Run in demo mode (no root / no capture privileges)
NETGHOST_DEV=1 docker compose run netghost
```

### Run Natively

```bash
# Install dependencies
pip install textual scapy rich

# Start (will try real capture, falls back to test mode)
NETGHOST_DEV=1 python -m netghost
```

> **Note:** Packet capture requires root privileges or `CAP_NET_RAW` / `CAP_NET_ADMIN` capabilities. The Docker setup handles this via `--cap-add`. Without them, the tool automatically falls back to demo mode with simulated traffic.

---

## Keybindings

| Key | Action |
|-----|--------|
| `↑ ↓` | Navigate traffic rows |
| `Enter` | Select row — show packet details in bottom panel |
| `S` | Start / Stop PCAP recording |
| `R` | Send RST packet to terminate selected TCP connection |
| `B` | Block the source IP of the selected packet |
| `L` | Toggle language (English ↔ Türkçe) |
| `Q` | Quit |

---

## Interface Layout

```
┌──────────────────────────────────────────────────────────┐
│  NetGhost v0.1.0    [wlo1]     ● REC                     │
├─────────────────────┬──────────────────┬─────────────────┤
│  LIVE TRAFFIC       │  CONNECTIONS     │  STATISTICS     │
│  [▼] 192.168.1.1   →│  10.0.0.5 → 8.8 │  Pkts/s:  1,234 │
│  ├─ Eth: AA:BB:CC   │  TCP 443 → 80   │  MB/s:    3.4   │
│  ├─ IP: v4 ttl=64   │  192.168.1.100   │  Active:  12    │
│  └─ TCP: SYN,ACK    │                 │  Uptime:  00:05 │
│  [▶] 10.0.0.5:53   →│                 │                  │
├─────────────────────┴──────────────────┴─────────────────┤
│  PACKET DETAILS — Layer 2 │ Layer 3 │ Layer 4 │ Payload  │
│  Ethernet: 00:1a:2b:3c:4d:5e → aa:bb:cc:dd:ee:ff        │
│  IPv4:     192.168.1.1 → 10.0.0.2    TTL=64             │
│  TCP:      443 → 54321  Flags: SYN,ACK  Window=65535    │
└──────────────────────────────────────────────────────────┘
```

---

## Docker on Linux

```bash
# Build
docker compose build

# Run with host networking (recommended for full visibility)
docker compose run netghost
```

The `docker-compose.yml` grants only the minimum capabilities required:
- `NET_RAW` — raw socket access (packet capture)
- `NET_ADMIN` — network administration (interception)

---

## Docker on macOS & Windows

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/), then the same commands work:

```bash
docker compose build
docker compose run netghost
```

Docker Desktop runs a Linux VM under the hood, so the tool operates in a Linux container on all platforms.

---

## Manual PCAP Recording

Press `S` to begin recording. Press `S` again to stop. The file is saved to your home directory as `netghost_YYYYMMDD_HHMMSS.pcap`.

---

## Architecture

```
NetGhost/
├── Dockerfile              # Multi-stage build (Alpine, ~80MB)
├── docker-compose.yml      # Capability config, host networking
├── requirements.txt        # Python dependencies
├── pyproject.toml          # Project metadata
└── netghost/
    ├── app.py              # Textual App entry point
    ├── i18n.py             # Bilingual translation engine
    ├── locales/            # en.json, tr.json
    ├── capture/
    │   ├── engine.py       # AsyncSniffer (Scapy) wrapper
    │   ├── parser.py       # Layer-by-layer packet parser
    │   ├── interceptor.py  # RST injection, IP blocking
    │   └── recorder.py     # PCAP file writer
    ├── models/
    │   └── packet.py       # Packet data model (dataclass)
    ├── ui/
    │   ├── css/cyberpunk.tcss    # Dark theme stylesheet
    │   ├── screens/main_screen.py
    │   └── widgets/         # TrafficTable, ConnectionPanel,
    │                        # StatsPanel, DetailPanel, InterfaceBar
    └── utils/
        └── network.py      # Interface discovery helpers
```

---

## Development

```bash
# Clone and install in editable mode
git clone https://github.com/labirend/NetGhost.git
cd NetGhost
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run in demo mode (no root needed)
NETGHOST_DEV=1 python -m netghost
```

---

## Roadmap

- [ ] Runtime interface switching
- [ ] BPF filter expressions (show only TCP / DNS / HTTP)
- [ ] Bandwidth timeline chart
- [ ] GeoIP enrichment
- [ ] Custom rule engine (alert on suspicious traffic)
- [ ] Dark / Light theme toggle

---

## License

MIT
