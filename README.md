# WireGuard CGNAT Relay

A lightweight UDP hole-punch relay written in pure Python (stdlib only).  
Allows a home server **behind CGNAT** to receive WireGuard connections through an AWS VPS with a public IP — no port forwarding required on the home side.

---

## How It Works

```
WireGuard Peer (internet)
        │
        │  UDP → VPS_IP:51820
        ▼
┌─────────────────────────┐
│        VPS (AWS)        │
│  wg_port   = :51820     │  ← external peers connect here
│  ctrl_port = :51821     │  ← home server registers here
└─────────┬───────────────┘
          │  wraps packet with peer-ID header
          │  UDP → cgnat_public_ip:ephemeral_port
          ▼
    [ CGNAT Cloud ]
          │  existing NAT mapping (created by home server outbound)
          ▼
┌─────────────────────────┐
│      Home Server        │
│  home_client.py socket  │ ← tunnel socket (created the NAT hole)
│  WireGuard :51820       │ ← local WG daemon receives relayed packets
└─────────────────────────┘
```

1. **Home server** dials out to `VPS:51821` → CGNAT creates a mapping
2. **VPS** records the home server's NAT endpoint
3. External WireGuard peer connects to `VPS:51820`
4. VPS wraps the packet with a peer-ID and forwards it to the home server's NAT endpoint via port 51821
5. Home server strips the wrapper and passes the raw WireGuard packet to the local daemon (`127.0.0.1:51820`)
6. Local WireGuard processes and replies via a per-peer pseudo-socket
7. Home server wraps the reply and sends it to VPS, which strips it and sends back to the external peer from port 51820

---

## Files

| File | Where it runs | Purpose |
|---|---|---|
| `vps_relay.py` | VPS | UDP relay server |
| `home_client.py` | Home server | Hole-punch client + relay |
| `config.ini` | Both (separate copies) | Configuration |
| `generate_secret.py` | Either | Generate shared secret |
| `vps_relay.service` | VPS | systemd service |
| `home_client.service` | Home server | systemd service |

---

## Step-by-step Setup

### Step 1 — Generate a shared secret

Run this **once** on any machine:

```bash
python3 generate_secret.py
```

Copy the output. You will paste it into `config.ini` on **both** the VPS and home server.

---

### Step 2 — Configure & deploy on VPS

```bash
# SSH into your VPS
mkdir -p /opt/wg-relay
cd /opt/wg-relay

# Upload vps_relay.py and config.ini
# (scp / rsync from your machine)
scp vps_relay.py config.ini user@vps:/opt/wg-relay/
```

Edit `/opt/wg-relay/config.ini` — only the `[relay]` section matters on VPS:

```ini
[relay]
secret    = <paste your secret here>
ctrl_port = 51821
wg_port   = 51820
bind_addr = 0.0.0.0
```

**Open firewall ports on AWS (Security Group):**

| Protocol | Port | Source |
|---|---|---|
| UDP | 51820 | 0.0.0.0/0 (WireGuard peers) |
| UDP | 51821 | 0.0.0.0/0 (home server registration) |

Install and start the service:

```bash
cp vps_relay.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vps_relay
systemctl status vps_relay
journalctl -fu vps_relay
```

---

### Step 3 — Configure WireGuard on home server

Your WireGuard config (`/etc/wireguard/wg0.conf`) needs **no changes** to the `[Interface]` section.  
For each `[Peer]` that connects via the relay, **remove or clear the `Endpoint`** line — WireGuard will learn the source address from incoming packets automatically.

> If your WireGuard peers need a static endpoint to initiate connections **from**, set `Endpoint = VPS_IP:51820` in their client configs (not on the home server).

Example home server `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address    = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <home_server_private_key>

[Peer]
PublicKey  = <peer_public_key>
AllowedIPs = 10.0.0.2/32
# No Endpoint here — VPS relay handles routing
```

---

### Step 4 — Deploy home client

```bash
mkdir -p /opt/wg-relay
cd /opt/wg-relay
scp home_client.py config.ini user@homeserver:/opt/wg-relay/
```

Edit `/opt/wg-relay/config.ini` — only the `[client]` section matters on home server:

```ini
[client]
secret          = <same secret as VPS>
vps_ip          = <your VPS public IP>
ctrl_port       = 51821
wg_local_port   = 51820
local_bind_port = 0
```

Start WireGuard first, then the client:

```bash
wg-quick up wg0

cp home_client.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now home_client
systemctl status home_client
journalctl -fu home_client
```

---

### Step 5 — Configure WireGuard peers (external clients)

On each WireGuard peer that wants to connect, set the endpoint to the **VPS public IP**:

```ini
[Peer]
PublicKey  = <home_server_public_key>
AllowedIPs = 10.0.0.0/24
Endpoint   = VPS_IP:51820       ← public IP of your VPS, NOT your home IP
```

---

## Verifying It Works

**On VPS** — watch for registration:

```bash
journalctl -fu vps_relay
# Should show:
# Home server registered: (your_cgnat_ip, port)
```

**Test packet relay** (from any machine):

```bash
# Send a test UDP packet to VPS WG port
echo "test" | nc -u VPS_IP 51820
```

VPS logs should show a new WG peer detected.

**Initiate WireGuard handshake** from an external peer:

```bash
wg-quick up wg0
ping 10.0.0.1   # home server WG IP
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Home client shows "Not registered" | VPS not reachable on 51821 | Check Security Group UDP 51821 rule |
| VPS shows bad HMAC | Secret mismatch | Re-run `generate_secret.py`, update both configs |
| Stale timestamp error | Clock skew > 60 s | `ntpdate -s pool.ntp.org` on both machines |
| WireGuard handshake fails | WG not listening locally | `wg show` — confirm ListenPort=51820 |
| Tunnel drops after ~30 min | CGNAT timeout | Reduce `KEEPALIVE_INTERVAL` in home_client.py to 15 s |

---

## NAT Keepalive Tuning

CGNAT providers vary in their UDP NAT timeout (typically 30–300 s). If you see intermittent drops, reduce the keepalive interval. Edit `home_client.py`:

```python
KEEPALIVE_INTERVAL = 15   # reduce if your CGNAT is aggressive
```

---

## Security Notes

- The shared secret uses **HMAC-SHA256** with a replay-prevention timestamp (± 60 s window)
- Only one home server can register at a time per relay instance
- WireGuard's own **public-key cryptography** protects the VPN traffic — the relay sees only ciphertext
- Consider adding UFW/iptables rules on VPS to rate-limit UDP to the two relay ports

---

## Requirements

- Python 3.7+ (uses `asyncio` — no third-party packages)
- WireGuard running on the home server (`wg-tools` / `wireguard-tools`)
- A VPS with a static public IP (AWS EC2, Lightsail, etc.)
