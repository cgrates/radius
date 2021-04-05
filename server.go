package radigo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/cgrates/radigo/codecs"
)

const (
	MetaDefault  = "*default" // default client
	MaxPacketLen = 4095
)

// NewSecrets intantiates Secrets
func NewSecrets(sts map[string]string) *Secrets {
	if sts == nil {
		sts = make(map[string]string)
	}
	return &Secrets{secrets: sts}
}

// Secrets centralizes RADIUS secrets so it can be safely accessed over different server instances
type Secrets struct {
	sync.RWMutex
	secrets map[string]string
}

// GetSecret returns secret for specific instanceID
// Returns default if no instanceID found
func (sts *Secrets) GetSecret(instanceID string) (scrt string) {
	sts.RLock()
	scrt, hasKey := sts.secrets[instanceID]
	if !hasKey {
		scrt = sts.secrets[MetaDefault]
	}
	sts.RUnlock()
	return
}

func connIDFromAddr(addr string) (connID string) {
	if idx := strings.Index(addr, "]:"); idx != -1 {
		connID = addr[1:idx] // ipv6 addr
	} else {
		connID = strings.Split(addr, ":")[0] // most likely ipv4 addr
	}
	return
}

// syncedTCPConn writes replies over a TCP connection
type syncedTCPConn struct {
	connID string
	conn   net.Conn
}

func (c *syncedTCPConn) getConnID() string {
	return c.connID
}

func (c *syncedTCPConn) write(b []byte) (err error) {
	_, err = c.conn.Write(b)
	return
}

func (c *syncedTCPConn) remoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// syncedUDPConn write replies over a UDP connection
type syncedUDPConn struct {
	connID string
	addr   net.Addr
	pc     net.PacketConn
}

func (c *syncedUDPConn) getConnID() string {
	return c.connID
}

func (c *syncedUDPConn) write(b []byte) (err error) {
	_, err = c.pc.WriteTo(b, c.addr)
	return
}

func (c *syncedUDPConn) remoteAddr() net.Addr {
	return c.addr
}

// syncedConn is the interface for securely writing on both UDP and TCP connections
type syncedConn interface {
	getConnID() string
	write([]byte) error
	remoteAddr() net.Addr
}

// sendReply writes the reply over the synced connection
func sendReply(synConn syncedConn, rply *Packet) (err error) {
	var buf [MaxPacketLen]byte
	var n int
	n, err = rply.Encode(buf[:])
	if err != nil {
		return
	}
	return synConn.write(buf[:n])
}

func NewServer(net, addr string, secrets *Secrets, dicts *Dictionaries,
	reqHandlers map[PacketCode]func(*Packet) (*Packet, error),
	avpCoders map[string]codecs.AVPCoder) *Server {
	coder := NewCoder()
	for k, v := range avpCoders {
		coder[k] = v
	}
	return &Server{net: net, addr: addr, secrets: secrets,
		dicts: dicts, reqHandlers: reqHandlers, coder: coder}
}

// Server represents a single listener on a port
type Server struct {
	net         string                                        // tcp, udp ...
	addr        string                                        // host:port or :port
	secrets     *Secrets                                      // client bounded secrets, *default for server wide
	dicts       *Dictionaries                                 // client bounded dictionaries, *default for server wide
	reqHandlers map[PacketCode]func(*Packet) (*Packet, error) // map[PacketCode]handler, 0 for default
	coder       Coder                                         // codecs for AVP values
	rhMux       sync.RWMutex                                  // protects reqHandlers
}

// RegisterHandler registers a new handler after the server was instantiated
// useful for live server reloads
func (s *Server) RegisterHandler(code PacketCode, hndlr func(*Packet) (*Packet, error)) {
	s.rhMux.Lock()
	s.reqHandlers[code] = hndlr
	s.rhMux.Unlock()
}

// handleRcvBytes is common method for both udp and tcp to handle received bytes over network
func (s *Server) handleRcvedBytes(rcv []byte, synConn syncedConn) {
	if !isAuthenticReq(rcv, []byte(s.secrets.GetSecret(synConn.getConnID()))) {
		return
	}
	pkt := &Packet{secret: s.secrets.GetSecret(synConn.getConnID()),
		dict:  s.dicts.GetInstance(synConn.getConnID()),
		coder: s.coder, addr: synConn.remoteAddr()}
	if err := pkt.Decode(rcv); err != nil {
		log.Printf("error: <%s> when decoding packet", err.Error())
		return
	}
	s.rhMux.RLock()
	hndlr, hasKey := s.reqHandlers[pkt.Code]
	s.rhMux.RUnlock()
	var rply *Packet
	if !hasKey {
		log.Printf("error: <no handler for packet with code: %d>", pkt.Code)
		rply = pkt.NegativeReply("no handler")
		go func() {
			if err := sendReply(synConn, rply); err != nil {
				log.Printf("error: <%s> sending reply", err.Error())
			}
		}()
		return
	}

	go func() { // execute the handler asynchronously
		rply, err := hndlr(pkt)
		if err != nil {
			rply = pkt.NegativeReply(err.Error())
		}
		if rply == nil {
			log.Printf("warning: empty reply received from handler")
			return
		}
		if err := sendReply(synConn, rply); err != nil {
			log.Printf("error: <%s> sending reply", err.Error())
		}
	}()
}

// handleConnection will listen on a single inbound connection for packets
// disconnects on error or unexpected packet length
// calls the handler synchronously and returns it's answer
func (s *Server) handleTCPConn(conn net.Conn) {
	synConn := &syncedTCPConn{conn: conn,
		connID: connIDFromAddr(conn.RemoteAddr().String())}
	for {
		var b [MaxPacketLen]byte
		n, err := conn.Read(b[:])
		if err != nil {
			log.Printf("error: <%s> when reading packets, disconnecting...", err.Error())
			conn.Close()
			return
		} else if uint16(n) != binary.BigEndian.Uint16(b[2:4]) {
			log.Printf("error: unexpected packet length, disconnecting...")
			conn.Close()
			return
		}
		s.handleRcvedBytes(b[:n], synConn)
	}
}

func (s *Server) listenAndServeUDP(stopChan <-chan struct{}) error {
	pc, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		return err
	}
	go func() {
		<-stopChan
		pc.Close()
	}()
	return s.serveUDP(stopChan, pc)
}

func (s *Server) serveUDP(stopChan <-chan struct{}, pc net.PacketConn) error {
	for {
		select {
		case <-stopChan:
			return nil
		default:
		}
		var b [MaxPacketLen]byte
		n, addr, err := pc.ReadFrom(b[:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("error: <%s> when reading packets over udp", err.Error())
			continue
		} else if uint16(n) != binary.BigEndian.Uint16(b[2:4]) {
			log.Printf("error: unexpected packet length received over UDP, should be: <%d>, received: <%d>",
				uint16(n), binary.BigEndian.Uint16(b[2:4]))
		}
		s.handleRcvedBytes(b[:n],
			&syncedUDPConn{connID: connIDFromAddr(addr.String()), addr: addr, pc: pc})
	}
}

func (s *Server) listenAndServeTCP(stopChan <-chan struct{}) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		log.Printf("RadiusServer, ListenAndServe, err %s\n", err.Error())
		return err
	}
	go func() {
		<-stopChan
		ln.Close()
	}()
	return s.serveTCP(stopChan, ln)
}

func (s *Server) serveTCP(stopChan <-chan struct{}, ln net.Listener) error {
	for {
		select {
		case <-stopChan:
			return nil
		default:
		}
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("error: <%s>, when establishing new connection", err.Error())
			continue
		}
		go s.handleTCPConn(conn)
	}
}

// ListenAndServe binds to a port and serves requests
func (s *Server) ListenAndServe(stopChan <-chan struct{}) error {
	switch s.net {
	case "udp":
		return s.listenAndServeUDP(stopChan)
	case "tcp":
		return s.listenAndServeTCP(stopChan)
	default:
		return fmt.Errorf("unsupported network: <%s>", s.net)
	}
}
