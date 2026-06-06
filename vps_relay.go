package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
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
	authKey     []byte
	homeEp      *net.UDPAddr
	homeTs      time.Time
	peersByID   map[uint32]*Peer
	peersByAddr map[string]*Peer
	nextPeerID  uint32
	pktFwd      uint64
	pktRet      uint64
	drops       uint64
}

func NewRelay(bindAddr string, wgPort int, authKey string) *Relay {
	return &Relay{
		wgPort:      wgPort,
		bindAddr:    bindAddr,
		authKey:     []byte(authKey),
		peersByID:   make(map[uint32]*Peer),
		peersByAddr: make(map[string]*Peer),
		nextPeerID:  1,
	}
}

func signPacket(data []byte, key []byte) []byte {
	ts := uint64(time.Now().UnixMilli())
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], ts)

	msg := make([]byte, len(data)+8)
	copy(msg, data)
	copy(msg[len(data):], tsBytes[:])

	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	signature := mac.Sum(nil)

	return append(msg, signature...)
}

func verifyPacket(data []byte, key []byte) ([]byte, bool) {
	if len(data) < 40 { // at least 8 byte timestamp + 32 byte HMAC
		return nil, false
	}
	macOffset := len(data) - 32
	message := data[:macOffset]
	signature := data[macOffset:]

	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(signature, expectedMAC) {
		return nil, false
	}

	tsOffset := macOffset - 8
	ts := binary.BigEndian.Uint64(message[tsOffset:macOffset])
	now := uint64(time.Now().UnixMilli())

	diff := int64(now) - int64(ts)
	if diff < -5000 || diff > 10000 { // Allow 5 sec delay, 10 sec clock drift future
		return nil, false
	}

	return message[:tsOffset], true
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

	var payload []byte
	var ok bool
	var wgBytes []byte

	// If it's a DataReply, the header is exactly 49 bytes (MAGIC(4) + TYPE(1) + PEER(4) + TS(8) + HMAC(32))
	if msgType == MsgDataReply {
		if len(data) < 49 {
			return
		}
		payload, ok = verifyPacket(data[:49], r.authKey)
		wgBytes = data[49:]
	} else {
		payload, ok = verifyPacket(data, r.authKey)
	}

	if !ok {
		log.Printf("Dropped invalid/spoofed control packet from %s", addr.String())
		return
	}

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
		ack := append([]byte(nil), Magic...)
		ack = append(ack, MsgAck)
		conn.WriteToUDP(signPacket(ack, r.authKey), addr)

	case MsgKeepalive:
		if r.homeEp != nil && r.homeEp.String() == addr.String() {
			r.homeTs = time.Now()
			ack := append([]byte(nil), Magic...)
			ack = append(ack, MsgAck)
			conn.WriteToUDP(signPacket(ack, r.authKey), addr)
		} else {
			log.Printf("Keepalive from unknown home: %s", addr.String())
		}

	case MsgDataReply:
		if r.homeEp == nil || r.homeEp.String() != addr.String() {
			return
		}
		peerID := binary.BigEndian.Uint32(payload[5:9])
		peer, exists := r.peersByID[peerID]
		if exists {
			peer.LastSeen = time.Now()
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

		hdr := make([]byte, 10)
		binary.BigEndian.PutUint32(hdr[0:4], peer.ID)
		ipBytes := addr.IP.To4()
		if ipBytes == nil {
			ipBytes = net.ParseIP("0.0.0.0").To4()
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

	// Create forward packet header: MAGIC(4) | MsgDataFwd(1) | HDR(10)
	hdr := make([]byte, 15)
	copy(hdr[0:4], Magic)
	hdr[4] = MsgDataFwd
	copy(hdr[5:15], peer.PackedHdr)
	
	// Sign only the header
	signedHdr := signPacket(hdr, r.authKey)
	
	// Append WG data
	fwd := make([]byte, len(signedHdr)+len(data))
	copy(fwd, signedHdr)
	copy(fwd[len(signedHdr):], data)
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
	authKey, ok := config["auth_key"]
	if !ok || authKey == "" || authKey == "CHANGE_ME_TO_A_SECURE_RANDOM_STRING" {
		log.Fatalf("Missing or default 'auth_key' in [relay] section of %s", *cfgPath)
	}

	relay := NewRelay(bind, port, authKey)
	relay.run()
}
