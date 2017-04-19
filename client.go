package radigo

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
	"time"
)

// successive Fibonacci numbers.
func fib() func() int {
	a, b := 0, 1
	return func() int {
		a, b = b, a+b
		return a
	}
}

// packetReplyHandler caches the original packet and handler for it
type packetReplyHandler struct {
	pkt     *Packet
	handler func(*Packet)
}

// NewClient creates a new client and connects it to the address
func NewClient(net, address string, secret string, dictionary *Dictionary, connAttempts int, logger *log.Logger) (*Client, error) {
	clnt := &Client{net: net, address: address, secret: secret, dictionary: dictionary,
		connAttempts: connAttempts, activeReqs: make(map[uint8]*packetReplyHandler), logger: logger}
	if connAttempts == 0 {
		connAttempts = 1 // at least one connection
	}
	if err := clnt.connect(connAttempts); err != nil {
		return nil, err
	}
	return clnt, nil
}

// Client is a thread-safe RADIUS client
type Client struct {
	conn         net.Conn
	connMux      sync.RWMutex   // protects the connection
	stopReading  *chan struct{} // signals stop reading of events
	net          string         // udp/tcp
	address      string
	secret       string
	dictionary   *Dictionary
	connAttempts int
	activeReqs   map[uint8]*packetReplyHandler // keep record of sent packets for matching with replies
	aReqsMux     sync.Mutex                    // protects activeRequests
	logger       *log.Logger
}

func (c *Client) connect(connAttempts int) (err error) {
	if connAttempts == 0 {
		return
	}
	if c.conn != nil {
		c.disconnect()
	}
	c.connMux.Lock()
	connDelay := fib()
	var i int
	for {
		i++
		if conn, err := net.Dial(c.net, c.address); err == nil {
			c.conn = conn
			stopReading := make(chan struct{})
			c.stopReading = &stopReading
			go c.readReplies(stopReading)
			break
		}
		if connAttempts != -1 && i >= connAttempts { // Maximum reconnects reached, -1 for infinite reconnects
			break
		}
		time.Sleep(time.Duration(connDelay()) * time.Second) // sleep before new attempt
	}
	c.connMux.Unlock()
	return
}

// disconnect does empties the connection and informs all handlers waiting for an answer
func (c *Client) disconnect() {
	c.connMux.Lock()
	if c.conn != nil {
		c.conn = nil
	}
	if c.stopReading != nil {
		close(*c.stopReading)
		c.stopReading = nil
	}
	c.connMux.Unlock()
	c.aReqsMux.Lock()
	for key, pHndlr := range c.activeReqs { // close all active requests with error
		delete(c.activeReqs, key)
		go pHndlr.handler(pHndlr.pkt.NegativeReply("connection lost"))
	}
	c.aReqsMux.Unlock()
}

func (c *Client) readReplies(stopReading chan struct{}) {
	for {
		select {
		case <-stopReading:
			return
		default: // Unlock waiting here
		}
		var b [4096]byte
		n, err := c.conn.Read(b[:])
		if err != nil {
			c.logger.Println(err.Error())
			c.disconnect()
			break
		} else if uint16(n) != binary.BigEndian.Uint16(b[2:4]) {
			c.logger.Println("error: unexpected packet length received")
			c.disconnect()
			break
		}
		rply := &Packet{secret: c.secret, dict: c.dictionary}
		if err = rply.Decode(b[:n]); err != nil {
			log.Printf("error: <%s> when decoding packet", err.Error())
			continue
		}
		c.aReqsMux.Lock()
		pktHndlr, has := c.activeReqs[rply.Identifier]
		delete(c.activeReqs, rply.Identifier)
		c.aReqsMux.Unlock()
		if !has {
			log.Printf("error: no handler for packet with code: %d", rply.Code)
			continue
		}
		go pktHndlr.handler(rply)
	}
}
