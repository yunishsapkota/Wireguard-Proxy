#!/usr/bin/env python3
"""
home_client.py — Hole-punch client (runs on home server behind CGNAT)
======================================================================
1. Opens a UDP socket → connects to VPS:ctrl_port
   (this outbound packet creates the NAT mapping in your CGNAT)
2. Sends REGISTER so the VPS records your NAT endpoint
3. Sends KEEPALIVE every 20 s to prevent NAT mapping expiry
4. When VPS forwards a WireGuard packet:
     → creates a pseudo-socket for that external peer
     → delivers raw WG bytes to local WireGuard at 127.0.0.1:wg_local_port
     → when WireGuard replies, wraps and sends back to VPS
5. Logs everything at DEBUG level so you can watch traffic in real time

Run:
  python home_client.py [config.ini]

Press Ctrl+C to stop.
"""

import asyncio
import logging
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("home")

# ── Wire protocol (must match vps_relay.py) ───────────────────────────────────

MAGIC          = b"\xDE\xAD\xBE\xEF"
MSG_REGISTER   = 0x01
MSG_KEEPALIVE  = 0x02
MSG_ACK        = 0x03
MSG_DATA_FWD   = 0x10
MSG_DATA_REPLY = 0x11

KEEPALIVE_INTERVAL = 20   # s  — must be less than your CGNAT's UDP idle timeout
ACK_TIMEOUT        = 90   # s  — if VPS goes quiet, re-register
PEER_TTL           = 120  # s  — close idle pseudo-sockets after this


# ── Per-external-peer pseudo-socket ───────────────────────────────────────────

class _PseudoProto(asyncio.DatagramProtocol):
    """
    A tiny local UDP socket sitting between the home_client and WireGuard.
    WireGuard replies here; we forward them back to the VPS tunnel.
    """
    def __init__(self, peer_id: int, on_reply):
        self.peer_id  = peer_id
        self._reply   = on_reply   # fn(peer_id, bytes)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        log.debug(f"WG→relay  id={self.peer_id}  {len(data)} B")
        self._reply(self.peer_id, data)

    def error_received(self, exc):
        log.error(f"pseudo-peer {self.peer_id} error: {exc}")


@dataclass
class PseudoPeer:
    peer_id:   int
    peer_addr: Tuple[str, int]   # original external peer (logging only)
    transport: object = field(default=None, repr=False)
    last_seen: float  = field(default_factory=time.monotonic)


# ── Main client ───────────────────────────────────────────────────────────────

class HomeClient:
    def __init__(self, cfg: dict):
        self.vps_addr   = (cfg["vps_ip"], cfg["ctrl_port"])
        self.wg_local   = ("127.0.0.1",  cfg["wg_local_port"])
        self.local_port = cfg["local_bind_port"]

        self.registered  = False
        self.last_ack    = 0.0
        self.tunnel_tx   = None

        self._peers: Dict[int, PseudoPeer] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ── Outbound packets ──────────────────────────────────────────────────────

    def _send(self, msg_type: int, payload: bytes = b""):
        pkt = MAGIC + bytes([msg_type]) + payload
        self.tunnel_tx.sendto(pkt, self.vps_addr)

    def _register(self):
        self._send(MSG_REGISTER)
        log.info(f"REGISTER → {self.vps_addr}")

    def _keepalive(self):
        self._send(MSG_KEEPALIVE)
        log.debug("KEEPALIVE →")

    def _reply_to_vps(self, peer_id: int, wg_bytes: bytes):
        hdr = struct.pack("!I", peer_id)
        self._send(MSG_DATA_REPLY, hdr + wg_bytes)
        log.debug(f"relay→VPS  id={peer_id}  {len(wg_bytes)} B")

    # ── Tunnel protocol (this socket ↔ VPS) ──────────────────────────────────

    class _Tunnel(asyncio.DatagramProtocol):
        def __init__(self, c): self.c = c
        def connection_made(self, tx):
            self.c.tunnel_tx = tx
            sock = tx.get_extra_info("sockname")
            log.info(f"Tunnel socket  local={sock[0]}:{sock[1]}  vps={self.c.vps_addr}")
            self.c._register()
        def datagram_received(self, data, addr):
            self.c._on_vps(data)
        def error_received(self, exc):
            log.error(f"tunnel error: {exc}")
        def connection_lost(self, exc):
            log.warning(f"tunnel lost: {exc}")
            self.c.registered = False

    def _on_vps(self, data: bytes):
        if len(data) < 5 or data[:4] != MAGIC:
            return
        t       = data[4]
        payload = data[5:]

        if t == MSG_ACK:
            if not self.registered:
                log.info("VPS ACK received — registered ✓")
                self.registered = True
            self.last_ack = time.monotonic()

        elif t == MSG_DATA_FWD:
            # payload: peer_id(4) | src_ip(4) | src_port(2) | wg_bytes
            if len(payload) < 11:
                return
            peer_id   = struct.unpack("!I", payload[:4])[0]
            peer_ip   = socket.inet_ntoa(payload[4:8])
            peer_port = struct.unpack("!H", payload[8:10])[0]
            wg_bytes  = payload[10:]
            asyncio.ensure_future(
                self._to_wg(peer_id, (peer_ip, peer_port), wg_bytes)
            )

    # ── Relay to local WireGuard ──────────────────────────────────────────────

    async def _to_wg(self, peer_id: int, peer_addr: Tuple[str, int], wg_bytes: bytes):
        if peer_id not in self._peers:
            proto  = _PseudoProto(peer_id, self._reply_to_vps)
            tx, _  = await self._loop.create_datagram_endpoint(
                lambda: proto,
                local_addr  = ("127.0.0.1", 0),
                remote_addr = self.wg_local,
            )
            local_port = tx.get_extra_info("sockname")[1]
            peer = PseudoPeer(peer_id=peer_id, peer_addr=peer_addr, transport=tx)
            self._peers[peer_id] = peer
            log.info(
                f"New peer  id={peer_id}  ext={peer_addr}  "
                f"local_pseudo=127.0.0.1:{local_port}"
            )
        else:
            peer = self._peers[peer_id]
            peer.last_seen = time.monotonic()

        peer.transport.sendto(wg_bytes)
        log.debug(f"VPS→WG  id={peer_id}  {len(wg_bytes)} B")

    # ── Background tasks ──────────────────────────────────────────────────────

    async def _keepalive_loop(self):
        # Retry registration for up to 60 s
        for _ in range(12):
            await asyncio.sleep(5)
            if self.registered:
                break
            log.warning("Not registered yet — retrying…")
            self._register()
        if not self.registered:
            log.error(
                "Could not reach VPS after 60 s.\n"
                "  • Check vps_ip / ctrl_port in config.ini\n"
                "  • Check AWS Security Group: UDP 51821 open inbound\n"
                "  • Is vps_relay.py running on the VPS?"
            )

        while True:
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            if not self.registered:
                log.warning("Lost registration — re-registering…")
                self._register()
            else:
                self._keepalive()
                if time.monotonic() - self.last_ack > ACK_TIMEOUT:
                    log.warning(f"No ACK for {ACK_TIMEOUT} s — re-registering…")
                    self.registered = False
                    self._register()

    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(60)
            now   = time.monotonic()
            stale = [p for p in list(self._peers.values())
                     if now - p.last_seen > PEER_TTL]
            for p in stale:
                p.transport.close()
                del self._peers[p.peer_id]
                log.info(f"Closed idle pseudo-peer  id={p.peer_id}  ext={p.peer_addr}")

    # ── Run ───────────────────────────────────────────────────────────────────

    async def run(self):
        self._loop = asyncio.get_running_loop()
        log.info(f"Home client  VPS={self.vps_addr}  WG={self.wg_local}")

        transport, _ = await self._loop.create_datagram_endpoint(
            lambda: self._Tunnel(self),
            local_addr  = ("0.0.0.0", self.local_port),
            remote_addr = self.vps_addr,
        )

        try:
            await asyncio.gather(
                self._keepalive_loop(),
                self._cleanup_loop(),
            )
        finally:
            transport.close()
            for p in self._peers.values():
                p.transport.close()


# ── Config ────────────────────────────────────────────────────────────────────

def load_config(path: str = "config.ini") -> dict:
    import configparser
    cfg = configparser.ConfigParser()
    cfg.read(path)
    if "client" not in cfg:
        sys.exit(f"[ERROR] Missing [client] section in {path}")
    s = cfg["client"]
    if not s.get("vps_ip", "").strip():
        sys.exit("[ERROR] 'vps_ip' must be set in [client] section")
    return {
        "vps_ip":          s["vps_ip"].strip(),
        "ctrl_port":       int(s.get("ctrl_port",       "51821")),
        "wg_local_port":   int(s.get("wg_local_port",  "51820")),
        "local_bind_port": int(s.get("local_bind_port", "0")),
    }


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else "config.ini"
    try:
        asyncio.run(HomeClient(load_config(cfg_path)).run())
    except KeyboardInterrupt:
        log.info("Stopped.")
