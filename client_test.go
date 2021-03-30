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

// func TestClientreadReplies(t *testing.T) {
// 	stopRead := make(chan struct{})
// 	c := &Client{}
// 	close(stopRead)
// 	c.readReplies(stopRead)
// }

func TestClientreadReplies(t *testing.T) {
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
