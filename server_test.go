package radigo

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cgrates/radigo/codecs"
)

func TestServerNewSecrets(t *testing.T) {
	var sts map[string]string

	exp := &Secrets{
		secrets: make(map[string]string),
	}

	rcv := NewSecrets(sts)

	if !reflect.DeepEqual(rcv.secrets, exp.secrets) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestServerGetSecretKeyNotFound(t *testing.T) {
	sts := &Secrets{}

	exp := ""
	rcv := sts.GetSecret("test")

	if rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestServerconnIDFromAddr(t *testing.T) {
	exp := "ff02::"
	rcv := connIDFromAddr("[ff02::]:1024")

	if rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestServerUDPgetConnID(t *testing.T) {
	c := &syncedUDPConn{
		connID: "testID",
	}

	exp := "testID"
	rcv := c.getConnID()

	if rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestServerUDPwrite(t *testing.T) {
	c := &syncedUDPConn{
		addr: &net.IPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Zone: AddressValue,
		},
		pc: &net.IPConn{},
	}

	b := make([]byte, 0)
	experr := "invalid argument"
	err := c.write(b)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestServerUDPremoteAddr(t *testing.T) {
	c := &syncedUDPConn{
		addr: &net.IPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Zone: AddressValue,
		},
	}

	exp := &net.IPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Zone: AddressValue,
	}
	rcv := c.remoteAddr()

	if rcv.String() != exp.String() {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestServersendReply(t *testing.T) {
	rply := &Packet{
		AVPs: []*AVP{
			{},
		},
	}
	var synConn syncedConn

	experr := fmt.Sprintf("avp: %+v, no value", rply.AVPs[0])
	err := sendReply(synConn, rply)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestServerNewServer(t *testing.T) {
	net := ""
	addr := ""
	secrets := &Secrets{}
	dicts := &Dictionaries{}
	var reqHandlers map[PacketCode]func(*Packet) (*Packet, error)
	avpCoders := map[string]codecs.AVPCoder{
		"key": codecs.IntegerCodec{},
	}

	exp := &Server{
		net:         net,
		addr:        addr,
		secrets:     secrets,
		dicts:       dicts,
		reqHandlers: reqHandlers,
		coder: map[string]codecs.AVPCoder{
			"address": codecs.AddressCodec{},
			"integer": codecs.IntegerCodec{},
			"ipaddr":  codecs.AddressCodec{},
			"key":     codecs.IntegerCodec{},
			"octets":  codecs.OctetsCodec{},
			"string":  codecs.StringCodec{},
			"text":    codecs.TextCodec{},
			"time":    codecs.TimeCodec{},
		},
	}
	rcv := NewServer(net, addr, secrets, dicts, reqHandlers, avpCoders)

	if !reflect.DeepEqual(rcv, exp) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestServerRegisterHandler(t *testing.T) {
	code := PacketCode(1)
	var hndlr func(*Packet) (*Packet, error)
	srv := &Server{
		reqHandlers: map[PacketCode]func(*Packet) (*Packet, error){
			code: hndlr,
		},
	}

	srv.RegisterHandler(code, hndlr)
}

// type syncedMock struct{}

// func (sM *syncedMock) getConnID() string {
// 	return ""
// }
// func (sM *syncedMock) write([]byte) error {
// 	return nil
// }
// func (sM *syncedMock) remoteAddr() net.Addr {
// 	return nil
// }

// func TestServerhandleRcvedBytes(t *testing.T) {
// 	srv := &Server{
// 		secrets: &Secrets{},
// 	}
// 	rcv := make([]byte, 0)
// 	synConn := syncedMock{}
// 	srv.handleRcvedBytes(rcv, synConn)
// }
type connMock struct {
	testcase string
}

func (cM *connMock) Read(b []byte) (n int, err error) {
	switch cM.testcase {
	case "readError":
		err = fmt.Errorf("read mock error")
	case "unexpectedLen":
		n = 2
	}
	return
}

func (cM *connMock) Write(b []byte) (n int, err error) {
	return
}

func (cM *connMock) Close() error {
	return nil
}

func (cM *connMock) LocalAddr() net.Addr {
	return nil
}

func (cM *connMock) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (cM *connMock) SetDeadline(t time.Time) error {
	return nil
}

func (cM *connMock) SetReadDeadline(t time.Time) error {
	return nil
}

func (cM *connMock) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestServerhandleTCPConnReadError(t *testing.T) {
	srv := &Server{}
	conn := &connMock{
		testcase: "readError",
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()
	explog := fmt.Sprintf("error: <%s> when reading packets, disconnecting...\n", "read mock error")
	srv.handleTCPConn(conn)

	if buf.String()[20:] != explog {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", explog, buf.String()[20:])
	}
}

func TestServerhandleTCPConnUnexpectedLen(t *testing.T) {
	srv := &Server{}
	conn := &connMock{
		testcase: "unexpectedLen",
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()
	explog := "error: unexpected packet length, disconnecting...\n"
	srv.handleTCPConn(conn)

	if buf.String()[20:] != explog {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", explog, buf.String()[20:])
	}
}

func TestServerListenAndServeUDPCasestopChan(t *testing.T) {
	stopChan := make(chan struct{})
	srv := &Server{
		net: "udp",
	}
	close(stopChan)

	err := srv.ListenAndServe(stopChan)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}
}

func TestServerListenAndServeFail(t *testing.T) {
	stopChan := make(chan struct{})
	srv := &Server{
		net: "invalid",
	}

	experr := fmt.Sprintf("unsupported network: <%s>", srv.net)
	err := srv.ListenAndServe(stopChan)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestServerlistenAndServeTCPCasestopChan(t *testing.T) {
	stopChan := make(chan struct{})
	srv := &Server{
		net: "tcp",
	}
	close(stopChan)

	err := srv.listenAndServeTCP(stopChan)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}
}

func TestServerlistenAndServeTCPInvalidAddress(t *testing.T) {
	stopChan := make(chan struct{})
	srv := &Server{
		net:  "tcp",
		addr: "invalid",
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	experr := "listen tcp: address invalid: missing port in address"
	explog := fmt.Sprintf("RadiusServer, ListenAndServe, err %s\n", experr)
	err := srv.listenAndServeTCP(stopChan)

	if err == nil || err.Error() != experr {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}

	if buf.String()[20:] != explog {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", explog, buf.String()[20:])
	}
}

func TestServerlistenAndServeUDPInvalidAddress(t *testing.T) {
	stopChan := make(chan struct{})
	srv := &Server{
		net:  "udp",
		addr: "invalid",
	}

	experr := "listen udp: address invalid: missing port in address"
	err := srv.listenAndServeUDP(stopChan)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestServerlistenAndServeUDPDefaultReadFail(t *testing.T) {
	stopChan := make(chan struct{})
	srv := &Server{
		net: "udp",
	}

	experr := "listen udp: address invalid: missing port in address"
	go func() {
		time.Sleep(10 * time.Millisecond)
		close(stopChan)
	}()
	err := srv.listenAndServeUDP(stopChan)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestServerlistenAndServeUDPDefaultReadSuccess(t *testing.T) {
	stopChan := make(chan struct{})
	srv := &Server{
		net:     "udp",
		addr:    "127.0.0.1:1234",
		secrets: NewSecrets(map[string]string{"key": "value"}),
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()
	p := make([]byte, 2048)
	go func() {
		conn, err := net.Dial(srv.net, "127.0.0.1:1234")
		if err != nil {
			t.Error(err)
		}
		defer conn.Close()
		conn.Write([]byte("Hi UDP Server, How are you doing?"))
		_, err = bufio.NewReader(conn).Read(p)
		if err != nil {
			t.Error(err)
		}
	}()

	go func() {
		time.Sleep(10 * time.Millisecond)
		close(stopChan)
	}()
	exp := fmt.Sprintf(
		"error: unexpected packet length received over UDP, should be: <%d>, received: <%d>\n",
		33,
		8277,
	)
	err := srv.listenAndServeUDP(stopChan)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}
	rcv := buf.String()[20:]
	if rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}

}
