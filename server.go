package radigo

import (
	"encoding/binary"
	"log"
	"net"
	"strings"
)

const (
	MetaDefault = "*default" // default client
)

func NewServer(net, addr string, secrets map[string]string, dicts map[string]*Dictionary, reqHandlers map[PacketCode]func(*Packet) (*Packet, error)) *Server {
	return &Server{net, addr, secrets, dicts, reqHandlers}
}

// Server represents a single listener on a port
type Server struct {
	net         string                                                     // tcp, udp ...
	addr        string                                                     // host:port or :port
	secrets     map[string]string                                          // client bounded secrets, *default for server wide
	dicts       map[string]*Dictionary                                     // client bounded dictionaries, *default for server wide
	reqHandlers map[PacketCode]func(req *Packet) (rply *Packet, err error) // map[PacketCode]handler, 0 for default
}

// listenConnection will listen on a single inbound connection for packets
// disconnects on error or unexpected packet length
func (s *Server) handleConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	var clntID string // IP of the client which should apply special secret or dictionary
	if idx := strings.Index(remoteAddr, "]:"); idx != -1 {
		clntID = remoteAddr[1:idx] // ipv6 addr
	} else {
		clntID = strings.Split(remoteAddr, ":")[0] // most likely ipv4 addr
	}
	for {
		var b [4096]byte
		n, err := conn.Read(b[:])
		if err != nil {
			log.Printf("error: <%s> when reading packets, disconnecting...", err.Error())
			conn.Close()
			return
		} else if uint16(n) != binary.BigEndian.Uint16(b[2:4]) {
			log.Printf("error: unexpected packet length, disconnecting...", err.Error())
			conn.Close()
			return
		}
		secret, hasKey := s.secrets[clntID]
		if !hasKey {
			secret = s.secrets[MetaDefault]
		}
		dict, hasKey := s.dicts[clntID]
		if !hasKey {
			dict = s.dicts[MetaDefault]
		}
		pkt := &Packet{secret: secret, dictionary: dict}
		if err = pkt.Decode(b[:n]); err != nil {
			log.Printf("error: <%s> when decoding packet", err.Error())
			continue
		}
		hndlr, hasKey := s.reqHandlers[pkt.Code]
		var rply *Packet
		if !hasKey {
			log.Printf("error: <no handler for packet with code: %d>", pkt.Code)
			rply = negativeReply(pkt, "no handler!")
		} else {
			var err error
			if rply, err = hndlr(pkt); err != nil {
				rply = negativeReply(pkt, err.Error())
			}
		}
		var buf [4096]byte
		n, err = rply.Encode(buf[:])
		if err != nil {
			log.Printf("error: <%s> on reply attempt", err.Error())
			continue
		}

		if _, err = conn.Write(buf[:n]); err != nil {
			log.Printf("error: <%s> on connection write", err.Error())
		}

		// execute handler for packet
		/*
			ips := pac.Attributes(NASIPAddress)

			if len(ips) != 1 {
				continue
			}

			ss := net.IP(ips[0].Value[0:4])

			service, ok := s.services[ss.String()]
			if !ok {
				log.Println("recieved request for unknown service: ", ss)
				continue

				//reject
			}
			npac, err := service.Authenticate(pac)
			if err != nil {
				return err
			}
			err = npac.Send(conn, addr)
			if err != nil {
				return err
			}
		*/
	}
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
		go s.handleConnection(conn)
	}
	return nil
}
