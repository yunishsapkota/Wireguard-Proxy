# WireGuard CGNAT Relay

A high-performance, single-socket UDP hole-punch relay written in **Go**.
Allows a home server **behind CGNAT** to receive WireGuard connections through an AWS VPS with a public IP — no port forwarding required on the home side.

---

## How It Works

```text
WireGuard Peer (internet)
        │
        │  UDP → VPS_IP:51820
        ▼
┌─────────────────────────┐
│        VPS (AWS)        │
│  wg_port = :51820       │  ← both external peers and home server connect here
└─────────┬───────────────┘
          │  wraps packet with peer-ID header & HMAC signature
          │  UDP → cgnat_public_ip:ephemeral_port
          ▼
    [ CGNAT Cloud ]
          │  existing NAT mapping (created by home server outbound)
          ▼
┌─────────────────────────┐
│      Home Server        │
│  home_client.go socket  │ ← tunnel socket (created the NAT hole)
│  WireGuard :51820       │ ← local WG daemon receives relayed packets
└─────────────────────────┘
```

1. **Home server** dials out to `VPS:51820` → CGNAT creates a mapping.
2. **VPS** authenticates the connection using an HMAC-SHA256 signature and records the home server's NAT endpoint.
3. External WireGuard peer connects to `VPS:51820`.
4. VPS wraps the packet with a peer-ID, signs the header with HMAC, and forwards it to the home server's NAT endpoint.
5. Home server verifies the signature, strips the wrapper, and passes the raw WireGuard packet to the local daemon (`127.0.0.1:51820`) via a dynamic pseudo-socket.
6. Local WireGuard processes and replies via the pseudo-socket.
7. Home server wraps the reply, signs it, and sends it to the VPS, which routes it back to the external peer.

---

## Files

| File | Where it runs | Purpose |
|---|---|---|
| `vps_relay.go` | VPS | High-throughput UDP relay server |
| `home_client.go` | Home server | Hole-punch client + multiplexer |
| `config.ini` | Both (separate copies) | Configuration & Pre-Shared Key |
| `vps_relay.service` | VPS | systemd service (optional) |
| `home_client.service` | Home server | systemd service (optional) |

---

## Security Model

The actual user data is **end-to-end encrypted by WireGuard**. The VPS cannot decrypt your traffic.
However, to prevent routing hijacking or denial-of-service, the relay protocol implements:
- **HMAC-SHA256 Signatures**: All control packets and internal routing headers are cryptographically signed using a Pre-Shared Key (`auth_key`).
- **Timestamp Replay Protection**: A 5-second Unix timestamp validation prevents attackers from recording and replaying legitimate registration packets.

*(Note: There is no strict maximum size for HMAC keys, but a random 32-64 character string is recommended. If you prefer to use a key file, simply paste its contents into the `config.ini` file).*

---

## Step-by-step Setup

### Step 1 — Kernel Buffer Tuning (CRITICAL)
Linux severely restricts UDP buffers by default (~208KB), which causes packet drops during WireGuard bursts, limiting speeds to ~1MBps. 
Run this on **both** your VPS and Home Server (if it's Linux):
```bash
sudo sysctl -w net.core.rmem_max=4194304
sudo sysctl -w net.core.wmem_max=4194304
```

### Step 2 — Configure & Deploy on VPS

1. Upload `vps_relay.go` and `config.ini` to your VPS.
2. Edit `config.ini`: set `wg_port = 51820` and set a secure random string for `auth_key`.
3. Open **UDP Port 51820** in your AWS Security Group.
4. Compile and run:
```bash
go build -o vps_relay vps_relay.go
./vps_relay
```

### Step 3 — Configure WireGuard on Home Server

Your WireGuard config (`/etc/wireguard/wg0.conf`) needs **no changes** to the `[Interface]` section.  
For each `[Peer]` that connects via the relay, **remove or clear the `Endpoint`** line — WireGuard will learn the source address from incoming packets automatically.

### Step 4 — Deploy Home Client

1. Copy `home_client.go` and `config.ini` to your Home Server.
2. Edit `config.ini` under `[client]`:
   - Set `vps_ip` to your VPS's public IP.
   - Set `auth_key` to the **exact same secret** you used on the VPS.
3. Compile and run:
```bash
go build -o home_client home_client.go
./home_client
```

### Step 5 — Configure WireGuard peers (external clients)

On each WireGuard peer (like your Android phone) that wants to connect, set the endpoint to the **VPS public IP**:

```ini
[Peer]
PublicKey  = <home_server_public_key>
AllowedIPs = 10.0.0.0/24
Endpoint   = VPS_IP:51820       ← public IP of your VPS, NOT your home IP
```

---

## Verifying It Works

**On VPS** — watch the console output:
```text
2024/01/01 12:00:00.000000 Home registered: 192.0.2.100:50000
```

**Initiate WireGuard handshake** from an external peer, and you should see a `New WG peer` log appear on both the VPS and Home Server.
