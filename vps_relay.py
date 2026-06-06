#!/usr/bin/env python3
"""
vps_relay.py — Relay server (runs on AWS VPS)
==============================================
Listens on two UDP sockets:
  ctrl_port (51821) — home server registers / sends keepalives here
  wg_port   (51820) — external WireGuard peers connect here

Run:
  python vps_relay.py [config.ini]

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
log = logging.getLogger("vps")

# ── Wire protocol ─────────────────────────────────────────────────────────────
#
#  All packets start with a 4-byte magic number so we can tell our control
#  messages apart from raw WireGuard traffic.
#
#  MAGIC(4) | type(1) | payload
#
#  MSG_REGISTER   (home→vps): no payload — just announces the NAT endpoint
#  MSG_KEEPALIVE  (home→vps): no payload — keeps NAT mapping alive
#  MSG_ACK        (vps→home): no payload — confirms receipt
#  MSG_DATA_FWD   (vps→home): peer_id(4) | src_ip(4) | src_port(2) | wg_bytes
#  MSG_DATA_REPLY (home→vps): peer_id(4) | wg_bytes

MAGIC = b"\xde\xad\xbe\xef"
MSG_REGISTER = 0x01
MSG_KEEPALIVE = 0x02
MSG_ACK = 0x03
MSG_DATA_FWD = 0x10
MSG_DATA_REPLY = 0x11

HOME_TIMEOUT = 90  # s — home considered gone after this
PEER_TIMEOUT = 120  # s — drop idle external-peer mapping after this


# ── Per-external-peer state ───────────────────────────────────────────────────


@dataclass
class Peer:
    peer_id: int
    addr: Tuple[str, int]
    last_seen: float = field(default_factory=time.monotonic)


# ── Relay ─────────────────────────────────────────────────────────────────────


class VPSRelay:
    def __init__(self, cfg: dict):
        self.ctrl_port = cfg["ctrl_port"]
        self.wg_port = cfg["wg_port"]
        self.bind_addr = cfg["bind_addr"]

        self.home_ep: Optional[Tuple[str, int]] = None
        self.home_last_seen: float = 0.0

        self._peers_by_id: Dict[int, Peer] = {}
        self._peers_by_addr: Dict[Tuple[str, int], Peer] = {}
        self._next_id = 1

        self.ctrl_tx = None  # sends to home server
        self.wg_tx = None  # sends to external WG peers

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _home_alive(self) -> bool:
        return (
            self.home_ep is not None
            and time.monotonic() - self.home_last_seen < HOME_TIMEOUT
        )

    def _ack(self) -> bytes:
        return MAGIC + bytes([MSG_ACK])

    def _fwd_packet(self, peer: Peer, wg_bytes: bytes) -> bytes:
        ip_b = socket.inet_aton(peer.addr[0])
        hdr = struct.pack("!I4sH", peer.peer_id, ip_b, peer.addr[1])
        return MAGIC + bytes([MSG_DATA_FWD]) + hdr + wg_bytes

    # ── Control socket handler ────────────────────────────────────────────────

    class _Ctrl(asyncio.DatagramProtocol):
        def __init__(self, r):
            self.r = r

        def connection_made(self, tx):
            self.r.ctrl_tx = tx
            log.info(f"Control socket  :{self.r.ctrl_port}")

        def datagram_received(self, data, addr):
            self.r._on_ctrl(data, addr)

        def error_received(self, exc):
            log.error(f"ctrl error: {exc}")

    def _on_ctrl(self, data: bytes, addr: Tuple[str, int]):
        if len(data) < 5 or data[:4] != MAGIC:
            return
        t = data[4]

        if t == MSG_REGISTER:
            changed = self.home_ep != addr
            self.home_ep = addr
            self.home_last_seen = time.monotonic()
            if changed:
                log.info(f"Home server registered  {addr}")
            else:
                log.debug(f"Home re-registered  {addr}")
            self.ctrl_tx.sendto(self._ack(), addr)

        elif t == MSG_KEEPALIVE:
            if addr == self.home_ep:
                self.home_last_seen = time.monotonic()
                self.ctrl_tx.sendto(self._ack(), addr)
                log.debug(f"keepalive from {addr}")
            else:
                log.warning(f"keepalive from unknown {addr}  (home={self.home_ep})")

        elif t == MSG_DATA_REPLY:
            self._on_home_reply(data[5:], addr)

    def _on_home_reply(self, payload: bytes, addr: Tuple[str, int]):
        if addr != self.home_ep:
            log.warning(f"DATA_REPLY from unexpected {addr}")
            return
        if len(payload) < 5:
            return
        peer_id = struct.unpack("!I", payload[:4])[0]
        wg_bytes = payload[4:]
        peer = self._peers_by_id.get(peer_id)
        if not peer:
            log.warning(f"DATA_REPLY for unknown peer_id={peer_id}")
            return
        peer.last_seen = time.monotonic()
        self.wg_tx.sendto(wg_bytes, peer.addr)
        log.debug(f"→ {peer.addr}  {len(wg_bytes)} B  (id={peer_id})")

    # ── WireGuard socket handler ───────────────────────────────────────────────

    class _WG(asyncio.DatagramProtocol):
        def __init__(self, r):
            self.r = r

        def connection_made(self, tx):
            self.r.wg_tx = tx
            log.info(f"WireGuard socket  :{self.r.wg_port}")

        def datagram_received(self, data, addr):
            self.r._on_wg(data, addr)

        def error_received(self, exc):
            log.error(f"wg error: {exc}")

    def _on_wg(self, data: bytes, addr: Tuple[str, int]):
        if not self._home_alive():
            log.warning(f"WG packet from {addr} dropped — home not registered")
            return
        peer = self._peers_by_addr.get(addr)
        if peer is None:
            peer = Peer(peer_id=self._next_id, addr=addr)
            self._next_id += 1
            self._peers_by_id[peer.peer_id] = peer
            self._peers_by_addr[addr] = peer
            log.info(f"New WG peer  {addr}  id={peer.peer_id}")
        else:
            peer.last_seen = time.monotonic()
        pkt = self._fwd_packet(peer, data)
        self.ctrl_tx.sendto(pkt, self.home_ep)
        log.debug(f"← {addr}  {len(data)} B  → home  (id={peer.peer_id})")

    # ── Background tasks ──────────────────────────────────────────────────────

    async def _cleanup(self):
        while True:
            await asyncio.sleep(30)
            now = time.monotonic()
            expired = [
                p
                for p in list(self._peers_by_id.values())
                if now - p.last_seen > PEER_TIMEOUT
            ]
            for p in expired:
                self._peers_by_id.pop(p.peer_id, None)
                self._peers_by_addr.pop(p.addr, None)
                log.info(f"Dropped idle peer  {p.addr}  id={p.peer_id}")

    async def _status(self):
        while True:
            await asyncio.sleep(30)
            home = f"✓ {self.home_ep}" if self._home_alive() else "✗ (none)"
            log.info(f"home={home}  peers={len(self._peers_by_id)}")

    # ── Run ───────────────────────────────────────────────────────────────────

    async def run(self):
        loop = asyncio.get_running_loop()
        log.info(f"VPS relay  ctrl=:{self.ctrl_port}  wg=:{self.wg_port}")

        ctrl_tx, _ = await loop.create_datagram_endpoint(
            lambda: self._Ctrl(self),
            local_addr=(self.bind_addr, self.ctrl_port),
        )
        wg_tx, _ = await loop.create_datagram_endpoint(
            lambda: self._WG(self),
            local_addr=(self.bind_addr, self.wg_port),
        )

        try:
            await asyncio.gather(self._cleanup(), self._status())
        finally:
            ctrl_tx.close()
            wg_tx.close()


# ── Config ────────────────────────────────────────────────────────────────────


def load_config(path: str = "config.ini") -> dict:
    import configparser

    cfg = configparser.ConfigParser()
    cfg.read(path)
    s = cfg["relay"] if "relay" in cfg else {}
    return {
        "ctrl_port": int(s.get("ctrl_port", "51821")),
        "wg_port": int(s.get("wg_port", "51820")),
        "bind_addr": s.get("bind_addr", "0.0.0.0"),
    }


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else "config.ini"
    try:
        asyncio.run(VPSRelay(load_config(cfg_path)).run())
    except KeyboardInterrupt:
        log.info("Stopped.")
