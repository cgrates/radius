package radigo

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/cgrates/radigo/codecs"
)

func TestClientfib(t *testing.T) {
	fib := fib()
	expected := 1
	f := fib()
	if expected != f {
		t.Fatalf("\nExpected: <%+v>,\nReceived: <%+v>", expected, f)
	}
	expected = 1
	f = fib()
	if expected != f {
		t.Fatalf("\nExpected: <%+v>,\nReceived: <%+v>", expected, f)
	}
	expected = 2
	f = fib()
	if expected != f {
		t.Fatalf("\nExpected: <%+v>,\nReceived: <%+v>", expected, f)
	}
	expected = 3
	f = fib()
	if expected != f {
		t.Fatalf("\nExpected: <%+v>,\nReceived: <%+v>", expected, f)
	}
	expected = 5
	f = fib()
	if expected != f {
		t.Fatalf("\nExpected: <%+v>,\nReceived: <%+v>", expected, f)
	}
}

func TestClientNewClientErrConnect(t *testing.T) {
	net := ""
	address := ""
	secret := ""
	dict := &Dictionary{}
	connAttempts := 0
	avpCoders := map[string]codecs.AVPCoder{}

	experr := "dial: unknown network "
	rcv, err := NewClient(net, address, secret, dict, connAttempts, avpCoders)

	if err == nil || err.Error() != experr {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}

	if rcv != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, rcv)
	}
}

func TestClientNewClientAddCoders(t *testing.T) {

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

	}))
	defer srv.Close()
	net := "udp"
	address := strings.TrimPrefix(srv.URL, "http://")
	secret := ""
	dict := &Dictionary{}
	connAttempts := 0
	avpCoders := map[string]codecs.AVPCoder{
		IntegerValue: codecs.IntegerCodec{},
	}
	rcv, err := NewClient(net, address, secret, dict, connAttempts, avpCoders)
	exp := rcv
	if err != nil {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestClientconnectZeroAttempts(t *testing.T) {
	c := &Client{}
	connAttempts := 0

	err := c.connect(connAttempts)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}
}

func TestClientconnectSleepAndDC(t *testing.T) {
	c := &Client{
		net:     "invalid",
		address: "127.0.0.11:1234",
		conn:    &net.UDPConn{},
	}
	connAttempts := 2

	experr := fmt.Sprintf("dial %s: unknown network %s", c.net, c.net)
	err := c.connect(connAttempts)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}
}

func TestClientreadReplies(t *testing.T) {
	stopRead := make(chan struct{})
	c := &Client{}

	close(stopRead)
	c.readReplies(stopRead)

	if len(stopRead) != 0 {
		t.Errorf("\nexpected 0,\nreceived: <%+v>", len(stopRead))
	}
}

func TestClientreadRepliesInvalidReadArgument(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	stopRead := make(chan struct{})
	c := &Client{
		conn: &net.UDPConn{},
	}

	c.readReplies(stopRead)

	explog := fmt.Sprintf("error <%s> when reading connection\n", "invalid argument")
	rcvlog := buf.String()[20:]

	if rcvlog != explog {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", explog, rcvlog)
	}
}
func TestClientreadRepliesUnexpectedLen(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	stopRead := make(chan struct{})
	c := &Client{
		conn: &connMock{
			testcase: "unexpectedLen",
		},
	}

	c.readReplies(stopRead)

	explog := "error <unexpected packet length received>\n"
	rcvlog := buf.String()[20:]

	if rcvlog != explog {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", explog, rcvlog)
	}
}
func TestClientreadRepliesDecodeFail(t *testing.T) {
	stopRead := make(chan struct{})

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	c1, c2 := net.Pipe()
	go func() {
		c2.Write([]byte{
			0x01, 0x01, 0x00, 0x21, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04,
			0x05, 0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06, 0x06, 0x22,
			0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x08, 0x08, 0x08, 0x08,
		})
		c2.Close()
	}()
	c := &Client{
		secret: "testSecret",
		dict:   &Dictionary{},
		coder:  Coder{},
		conn:   c1,
		activeReqs: map[uint8]*packetReplyHandler{
			1: {
				rplChn: make(chan *Packet, 1),
				pkt:    &Packet{},
			},
		},
	}

	c.readReplies(stopRead)
	close(stopRead)
	explog := fmt.Sprintf("error <%s> when decoding packet", "invalid length")
	rcvlog := buf.String()[20 : 20+len(explog)]

	if rcvlog != explog {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", explog, rcvlog)
	}
}
func TestClientreadReplies1(t *testing.T) {
	stopRead := make(chan struct{})

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	c1, c2 := net.Pipe()
	go func() {
		c2.Write([]byte{
			0x01, 0x01, 0x00, 0x21, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04,
			0x05, 0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
			0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x08, 0x08, 0x08, 0x08,
		})
		c2.Close()
	}()
	c := &Client{
		secret: "testSecret",
		dict:   &Dictionary{},
		coder:  Coder{},
		conn:   c1,
		activeReqs: map[uint8]*packetReplyHandler{
			2: {
				rplChn: make(chan *Packet, 1),
				pkt:    &Packet{},
			},
		},
	}

	c.readReplies(stopRead)
	close(stopRead)
	explog := fmt.Sprintf("error <no handler for packet with code: %d>", 1)
	rcvlog := buf.String()[20 : 20+len(explog)]

	if rcvlog != explog {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", explog, rcvlog)
	}
}

func TestClientSendRequestEncodeFail(t *testing.T) {
	req := &Packet{
		AVPs: []*AVP{
			{},
		},
	}
	c := &Client{
		secret: "testSecret",
		dict:   &Dictionary{},
	}

	experr := fmt.Sprintf("avp: %+v, no value", req.AVPs[0])
	rcv, err := c.SendRequest(req)

	if err == nil || err.Error() != experr {
		t.Fatalf("\nexpected: <%+v>,\nreceived: <%+v>", experr, err)
	}

	if rcv != nil {
		t.Errorf("\nexpected: <%+v>, \nreceived: <%+v>", nil, rcv)
	}
}

func TestClientSendRequestWriteFail(t *testing.T) {
	req := &Packet{
		Identifier: 1,
	}
	c := &Client{
		secret:     "testSecret",
		dict:       &Dictionary{},
		activeReqs: make(map[uint8]*packetReplyHandler),
		conn: &connMock{
			testcase: "writeError",
		},
	}

	experr := "write mock error"
	rcv, err := c.SendRequest(req)

	if err == nil || err.Error() != experr {
		t.Fatalf("\nexpected: <%+v>,\nreceived: <%+v>", experr, err)
	}

	if rcv != nil {
		t.Errorf("\nexpected: <%+v>, \nreceived: <%+v>", nil, rcv)
	}
}

func TestClientdisconnect(t *testing.T) {
	c := &Client{
		stopReading: make(chan struct{}),
	}

	c.disconnect()

	if len(c.stopReading) != 0 {
		t.Errorf("\nexpected 0,\nreceived: <%+v>", len(c.stopReading))
	}
}
