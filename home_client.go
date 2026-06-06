package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"flag"
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

	KeepaliveInt = 20 * time.Second
	AckTimeout   = 90 * time.Second
	PeerTTL      = 120 * time.Second
)

var Magic = []byte{0xDE, 0xAD, 0xBE, 0xEF}

type PseudoPeer struct {
	ID       uint32
	ExtAddr  string
	Conn     *net.UDPConn
	LastSeen time.Time
}

type Client struct {
	mu         sync.RWMutex
	vpsAddr    *net.UDPAddr
	wgLocal    *net.UDPAddr
	authKey    []byte
	tunnelConn *net.UDPConn
	registered bool
	lastAck    time.Time
	peers      map[uint32]*PseudoPeer
}

func NewClient(vpsStr string, wgLocalStr string, authKey string) *Client {
	vpsAddr, err := net.ResolveUDPAddr("udp", vpsStr)
	if err != nil {
		log.Fatalf("Failed to resolve VPS address: %v", err)
	}
	wgAddr, err := net.ResolveUDPAddr("udp", wgLocalStr)
	if err != nil {
		log.Fatalf("Failed to resolve WG Local address: %v", err)
	}

	return &Client{
		vpsAddr: vpsAddr,
		wgLocal: wgAddr,
		authKey: []byte(authKey),
		peers:   make(map[uint32]*PseudoPeer),
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
	if len(data) < 40 {
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
	if diff < -5000 || diff > 10000 {
		return nil, false
	}

	return message[:tsOffset], true
}

func (c *Client) run(localPort int) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: localPort})
	if err != nil {
		log.Fatalf("Failed to listen on tunnel port: %v", err)
	}
	c.tunnelConn = conn

	c.tunnelConn.SetReadBuffer(4 * 1024 * 1024)
	c.tunnelConn.SetWriteBuffer(4 * 1024 * 1024)

	log.Printf("Home client VPS=%s WG=%s", c.vpsAddr, c.wgLocal)
	log.Printf("Tunnel bound to %s", c.tunnelConn.LocalAddr())

	go c.keepaliveLoop()
	go c.cleanupLoop()

	buf := make([]byte, 65536)
	for {
		n, _, err := c.tunnelConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Tunnel read err: %v", err)
			continue
		}
		if n < 4 {
			continue
		}

		if bytes.Equal(buf[:4], Magic) {
			if n < 5 {
				continue
			}
			msgType := buf[4]
			
			var payload []byte
			var ok bool
			var wgBytes []byte

			if msgType == MsgDataFwd {
				if n < 55 { // MAGIC(4) + TYPE(1) + PEER(10) + TS(8) + HMAC(32)
					continue
				}
				payload, ok = verifyPacket(buf[:55], c.authKey)
				wgBytes = buf[55:n]
			} else {
				payload, ok = verifyPacket(buf[:n], c.authKey)
			}

			if !ok {
				continue
			}

			if msgType == MsgAck {
				c.mu.Lock()
				if !c.registered {
					log.Printf("VPS ACK — registered ✓")
					c.registered = true
				}
				c.lastAck = time.Now()
				c.mu.Unlock()
			} else if msgType == MsgDataFwd {
				peerID := binary.BigEndian.Uint32(payload[5:9])
				ip := net.IP(payload[9:13])
				port := binary.BigEndian.Uint16(payload[13:15])
				extAddr := (&net.UDPAddr{IP: ip, Port: int(port)}).String()

				c.mu.Lock()
				peer, exists := c.peers[peerID]
				if !exists {
					pConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
					if err == nil {
						pConn.SetReadBuffer(4 * 1024 * 1024)
						peer = &PseudoPeer{
							ID:      peerID,
							ExtAddr: extAddr,
							Conn:    pConn,
						}
						c.peers[peerID] = peer
						log.Printf("New peer id=%d ext=%s pseudo=%s", peerID, extAddr, pConn.LocalAddr())
						go c.pseudoPeerReadLoop(peer)
					}
				}
				if peer != nil {
					peer.LastSeen = time.Now()
				}
				c.mu.Unlock()

				if peer != nil {
					peer.Conn.WriteToUDP(wgBytes, c.wgLocal)
				}
			}
		}
	}
}

func (c *Client) pseudoPeerReadLoop(peer *PseudoPeer) {
	buf := make([]byte, 65536)

	// Prebuild reply header: MAGIC(4) | MsgDataReply(1) | ID(4)
	hdr := make([]byte, 9)
	copy(hdr[0:4], Magic)
	hdr[4] = MsgDataReply
	binary.BigEndian.PutUint32(hdr[5:9], peer.ID)

	for {
		n, _, err := peer.Conn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		c.mu.Lock()
		peer.LastSeen = time.Now()
		c.mu.Unlock()

		signedHdr := signPacket(hdr, c.authKey)
		reply := make([]byte, len(signedHdr)+n)
		copy(reply, signedHdr)
		copy(reply[len(signedHdr):], buf[:n])

		c.tunnelConn.WriteToUDP(reply, c.vpsAddr)
	}
}

func (c *Client) keepaliveLoop() {
	regPkt := []byte{0xDE, 0xAD, 0xBE, 0xEF, MsgRegister}
	keepPkt := []byte{0xDE, 0xAD, 0xBE, 0xEF, MsgKeepalive}

	for {
		c.mu.Lock()
		reg := c.registered
		ackElapsed := time.Since(c.lastAck)
		c.mu.Unlock()

		if !reg {
			signedPkt := signPacket(regPkt, c.authKey)
			c.tunnelConn.WriteToUDP(signedPkt, c.vpsAddr)
			log.Printf("REGISTER -> %s", c.vpsAddr)
		} else {
			signedPkt := signPacket(keepPkt, c.authKey)
			c.tunnelConn.WriteToUDP(signedPkt, c.vpsAddr)
			if ackElapsed > AckTimeout {
				log.Printf("No ACK for %v — re-registering...", AckTimeout)
				c.mu.Lock()
				c.registered = false
				c.mu.Unlock()
			}
		}
		time.Sleep(KeepaliveInt)
	}
}

func (c *Client) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for id, p := range c.peers {
			if now.Sub(p.LastSeen) > PeerTTL {
				p.Conn.Close()
				delete(c.peers, id)
				log.Printf("Closed idle pseudo-peer id=%d", id)
			}
		}
		c.mu.Unlock()
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

	config := parseINI(*cfgPath, "client")

	vpsIP, ok := config["vps_ip"]
	if !ok || vpsIP == "" {
		log.Fatalf("Missing 'vps_ip' in [client] section of %s", *cfgPath)
	}

	wgPort := "51820"
	if p, ok := config["wg_port"]; ok && p != "" {
		wgPort = p
	}
	vpsEndpoint := vpsIP + ":" + wgPort

	wgLocalPort := "51820"
	if p, ok := config["wg_local_port"]; ok && p != "" {
		wgLocalPort = p
	}
	wgLocal := "127.0.0.1:" + wgLocalPort

	localPort := 0
	if pStr, ok := config["local_bind_port"]; ok {
		if p, err := strconv.Atoi(pStr); err == nil {
			localPort = p
		}
	}
	
	authKey, ok := config["auth_key"]
	if !ok || authKey == "" || authKey == "CHANGE_ME_TO_A_SECURE_RANDOM_STRING" {
		log.Fatalf("Missing or default 'auth_key' in [client] section of %s", *cfgPath)
	}

	client := NewClient(vpsEndpoint, wgLocal, authKey)
	client.run(localPort)
}
