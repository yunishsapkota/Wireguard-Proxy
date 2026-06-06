package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MsgRegister  = 0x01
	MsgKeepalive = 0x02
	MsgAck       = 0x03
	MsgDataFwd   = 0x10
	MsgDataReply = 0x11

	HomeTimeout = 90 * time.Second
	PeerTimeout = 120 * time.Second
)

var Magic = []byte{0xDE, 0xAD, 0xBE, 0xEF}

type Peer struct {
	ID        uint32
	Addr      *net.UDPAddr
	PackedHdr []byte
	LastSeen  time.Time
}

type Relay struct {
	mu          sync.RWMutex
	wgPort      int
	bindAddr    string
	homeEp      *net.UDPAddr
	homeTs      time.Time
	peersByID   map[uint32]*Peer
	peersByAddr map[string]*Peer
	nextPeerID  uint32
	pktFwd      uint64
	pktRet      uint64
	drops       uint64
}

func NewRelay(bindAddr string, wgPort int) *Relay {
	return &Relay{
		wgPort:      wgPort,
		bindAddr:    bindAddr,
		peersByID:   make(map[uint32]*Peer),
		peersByAddr: make(map[string]*Peer),
		nextPeerID:  1,
	}
}

func (r *Relay) homeAlive() bool {
	return r.homeEp != nil && time.Since(r.homeTs) < HomeTimeout
}

func (r *Relay) run() {
	addr := fmt.Sprintf("%s:%d", r.bindAddr, r.wgPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("Invalid bind address: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to bind UDP: %v", err)
	}
	defer conn.Close()

	// Maximize buffer sizes for high throughput (4MB)
	conn.SetReadBuffer(4 * 1024 * 1024)
	conn.SetWriteBuffer(4 * 1024 * 1024)

	log.Printf("VPS relay running on %s", addr)

	go r.cleanupLoop()

	buf := make([]byte, 65536)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}
		if n < 4 {
			continue
		}

		// Discriminate packets based on Magic prefix
		if bytes.Equal(buf[:4], Magic) {
			r.handleControl(conn, buf[:n], raddr)
		} else {
			r.handleWG(conn, buf[:n], raddr)
		}
	}
}

func (r *Relay) handleControl(conn *net.UDPConn, data []byte, addr *net.UDPAddr) {
	if len(data) < 5 {
		return
	}
	msgType := data[4]

	r.mu.Lock()
	defer r.mu.Unlock()

	switch msgType {
	case MsgRegister:
		changed := r.homeEp == nil || r.homeEp.String() != addr.String()
		r.homeEp = addr
		r.homeTs = time.Now()
		if changed {
			log.Printf("Home registered: %s", addr.String())
		}
		conn.WriteToUDP(append(Magic, MsgAck), addr)

	case MsgKeepalive:
		if r.homeEp != nil && r.homeEp.String() == addr.String() {
			r.homeTs = time.Now()
			conn.WriteToUDP(append(Magic, MsgAck), addr)
		} else {
			log.Printf("Keepalive from unknown home: %s", addr.String())
		}

	case MsgDataReply:
		if r.homeEp == nil || r.homeEp.String() != addr.String() || len(data) < 9 {
			return
		}
		peerID := binary.BigEndian.Uint32(data[5:9])
		peer, exists := r.peersByID[peerID]
		if exists {
			peer.LastSeen = time.Now()
			wgBytes := data[9:]
			_, err := conn.WriteToUDP(wgBytes, peer.Addr)
			if err != nil {
				r.drops++
			} else {
				r.pktRet++
			}
		}
	}
}

func (r *Relay) handleWG(conn *net.UDPConn, data []byte, addr *net.UDPAddr) {
	r.mu.Lock()
	if !r.homeAlive() {
		r.mu.Unlock()
		return
	}

	addrStr := addr.String()
	peer, exists := r.peersByAddr[addrStr]
	if !exists {
		peer = &Peer{
			ID:   r.nextPeerID,
			Addr: addr,
		}
		r.nextPeerID++

		// Pre-pack the header: peer_id(4) + ip(4) + port(2) = 10 bytes
		hdr := make([]byte, 10)
		binary.BigEndian.PutUint32(hdr[0:4], peer.ID)
		ipBytes := addr.IP.To4()
		if ipBytes == nil {
			ipBytes = net.ParseIP("0.0.0.0").To4() // Fallback
		}
		copy(hdr[4:8], ipBytes)
		binary.BigEndian.PutUint16(hdr[8:10], uint16(addr.Port))
		peer.PackedHdr = hdr

		r.peersByID[peer.ID] = peer
		r.peersByAddr[addrStr] = peer
		log.Printf("New WG peer %s id=%d", addrStr, peer.ID)
	}
	peer.LastSeen = time.Now()
	homeEp := r.homeEp

	// Create forward packet: MAGIC(4) | MsgDataFwd(1) | HDR(10) | DATA
	fwd := make([]byte, 15+len(data))
	copy(fwd[0:4], Magic)
	fwd[4] = MsgDataFwd
	copy(fwd[5:15], peer.PackedHdr)
	copy(fwd[15:], data)
	r.mu.Unlock()

	_, err := conn.WriteToUDP(fwd, homeEp)

	r.mu.Lock()
	if err != nil {
		r.drops++
	} else {
		r.pktFwd++
	}
	r.mu.Unlock()
}

func (r *Relay) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		r.mu.Lock()
		now := time.Now()
		for id, p := range r.peersByID {
			if now.Sub(p.LastSeen) > PeerTimeout {
				delete(r.peersByID, id)
				delete(r.peersByAddr, p.Addr.String())
				log.Printf("Dropped idle peer %s id=%d", p.Addr.String(), p.ID)
			}
		}

		homeStr := "✗ (none)"
		if r.homeAlive() {
			homeStr = fmt.Sprintf("✓ %s", r.homeEp.String())
		}
		log.Printf("home=%s peers=%d fwd=%d ret=%d drops=%d", homeStr, len(r.peersByID), r.pktFwd, r.pktRet, r.drops)
		r.mu.Unlock()
	}
}

func parseINI(filename string, section string) map[string]string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Failed to open config %s: %v", filename, err)
	}
	defer file.Close()

	config := make(map[string]string)
	scanner := bufio.NewScanner(file)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = line[1 : len(line)-1]
			continue
		}
		if currentSection == section {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				valPart := parts[1]
				if idx := strings.IndexAny(valPart, "#;"); idx != -1 {
					valPart = valPart[:idx]
				}
				config[key] = strings.TrimSpace(valPart)
			}
		}
	}
	return config
}

func main() {
	cfgPath := flag.String("config", "config.ini", "Path to config file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	config := parseINI(*cfgPath, "relay")
	
	bind := "0.0.0.0"
	if b, ok := config["bind_addr"]; ok && b != "" {
		bind = b
	}
	port := 51820
	if pStr, ok := config["wg_port"]; ok {
		if p, err := strconv.Atoi(pStr); err == nil {
			port = p
		}
	}

	relay := NewRelay(bind, port)
	relay.run()
}
