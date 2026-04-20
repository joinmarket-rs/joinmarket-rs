# joinmarket-rs — Deployment Guide

## Key Storage

The hidden service Ed25519 identity key determines the `.onion` address. It must be kept on persistent storage and backed up. **If it is lost the .onion address is permanently gone.**

**tordaemon backend:** C Tor manages the key inside the `hidden_service_dir` configured in `joinmarket.cfg` (the `[MESSAGING:onion]` section). Do not delete the files in that directory.

**Arti backend:** Arti manages the key inside `<datadir>/` in its own keystore format, alongside Tor consensus and circuit state.

> **Production security note:** the optional Arti build currently inherits unresolved upstream advisories in transitive dependencies (`rsa`, `bincode`, `paste`). Prefer the default `tordaemon` backend for production until those upstream fixes land.


```
<datadir>/
├── arti-cache/     # Tor consensus cache (Arti managed)
├── arti-state/     # Tor circuit state (Arti managed)
└── keys/           # Ed25519 hidden service key (Arti keystore — DO NOT DELETE)
```

## Metrics Endpoint Hardening

Bind Prometheus metrics to loopback whenever possible:

```ini
--metrics-bind=127.0.0.1:9090
```

If you need remote scraping, expose the endpoint only through one of:

- a host firewall allowlist
- an authenticated reverse proxy with TLS
- an SSH tunnel from the Prometheus server

Do not publish the metrics listener directly to the public internet unless the information disclosure is acceptable for your environment.

## systemd Unit

```ini
[Unit]
Description=JoinMarket Directory Node (Rust)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/joinmarket-dn \
    --datadir=/var/lib/joinmarket \
    --metrics-bind=127.0.0.1:9090 \
    "Greetings from a Rust directory node"
User=joinmarket
Restart=on-failure
RestartSec=10s
LimitNOFILE=500000
MemoryMax=20G

[Install]
WantedBy=multi-user.target
```

## Linux Kernel Tuning (100k+ peers)

```bash
# /etc/sysctl.d/99-joinmarket-dn.conf
fs.file-max = 2000000
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_rmem = 4096 4096 16384
net.ipv4.tcp_wmem = 4096 4096 16384
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.netfilter.nf_conntrack_max = 2000000
```
