package radigo

import (
	"encoding/binary"
	"log"
	"net"
	"strings"
	"sync"
)

const (
	MetaDefault = "*default" // default client
)

// syncedConn queues replies
type syncedConn struct {
	sync.RWMutex
	conn net.Conn
}

type requestOriginator struct {
	req     *Packet
	synConn *syncedConn
}

// sendReply writes the reply over the synced connection
func sendReply(synConn *syncedConn, rply *Packet) (err error) {
	var buf [4096]byte
	var n int
	n, err = rply.Encode(buf[:])
	if err != nil {
		return
	}
	synConn.Lock()
	_, err = synConn.conn.Write(buf[:n])
	synConn.Unlock()
	return
}

func NewServer(net, addr string, secrets map[string]string, dicts map[string]*Dictionary,
	reqHandlers map[PacketCode]func(*Packet) (*Packet, error)) *Server {
	return &Server{net: net, addr: addr, secrets: secrets, dicts: dicts, reqHandlers: reqHandlers}
}

// Server represents a single listener on a port
type Server struct {
	net         string                                        // tcp, udp ...
	addr        string                                        // host:port or :port
	secrets     map[string]string                             // client bounded secrets, *default for server wide
	scrtMux     sync.RWMutex                                  // protects secrets
	dicts       map[string]*Dictionary                        // client bounded dictionaries, *default for server wide
	dMux        sync.RWMutex                                  // protects dicts
	reqHandlers map[PacketCode]func(*Packet) (*Packet, error) // map[PacketCode]handler, 0 for default
	rhMux       sync.RWMutex                                  // protects reqHandlers
}

// handleConnection will listen on a single inbound connection for packets
// disconnects on error or unexpected packet length
// calls the handler synchronously and returns it's answer
func (s *Server) handleConnection(synConn *syncedConn) {
	remoteAddr := synConn.conn.RemoteAddr().String()
	var clntID string // IP of the client which should apply special secret or dictionary
	if idx := strings.Index(remoteAddr, "]:"); idx != -1 {
		clntID = remoteAddr[1:idx] // ipv6 addr
	} else {
		clntID = strings.Split(remoteAddr, ":")[0] // most likely ipv4 addr
	}
	for {
		var b [4096]byte
		n, err := synConn.conn.Read(b[:])
		if err != nil {
			log.Printf("error: <%s> when reading packets, disconnecting...", err.Error())
			synConn.conn.Close()
			return
		} else if uint16(n) != binary.BigEndian.Uint16(b[2:4]) {
			log.Printf("error: unexpected packet length, disconnecting...")
			synConn.conn.Close()
			return
		}

		s.scrtMux.RLock()
		secret, hasKey := s.secrets[clntID]
		if !hasKey {
			secret = s.secrets[MetaDefault]
		}
		s.scrtMux.RUnlock()

		s.dMux.RLock()
		dict, hasKey := s.dicts[clntID]
		if !hasKey {
			dict = s.dicts[MetaDefault]
		}
		s.dMux.RUnlock()

		pkt := &Packet{secret: secret, dict: dict}
		if err = pkt.Decode(b[:n]); err != nil {
			log.Printf("error: <%s> when decoding packet", err.Error())
			continue
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
			continue
		}
		go func() { // execute the handler asynchronously
			rply, err := hndlr(pkt)
			if err != nil {
				rply = pkt.NegativeReply(err.Error())
			}
			if err := sendReply(synConn, rply); err != nil {
				log.Printf("error: <%s> sending reply", err.Error())
			}
		}()

	}
}

func (s *Server) RegisterHandler(code PacketCode, hndlr func(*Packet) (*Packet, error)) {
	s.rhMux.Lock()
	s.reqHandlers[code] = hndlr
	s.rhMux.Unlock()
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen(s.net, s.addr)
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("error: <%s>, when establishing new connection", err.Error())
			continue
		}
		go s.handleConnection(&syncedConn{conn: conn})
	}
	return nil
}
