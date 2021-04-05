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

type pcMock struct {
	testcase string
}

func (pM *pcMock) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, nil
}

func (pM *pcMock) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	switch pM.testcase {
	case "sendReply err":
		return 0, fmt.Errorf("WriteTo error")
	}
	return 0, nil
}

func (pM *pcMock) Close() error {
	return nil
}

func (pM *pcMock) LocalAddr() net.Addr {
	return nil
}

func (pM *pcMock) SetDeadline(t time.Time) error {
	return nil
}

func (pM *pcMock) SetReadDeadline(t time.Time) error {
	return nil
}

func (pM *pcMock) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestServerhandleRcvedBytesDecodeFail(t *testing.T) {
	srv := &Server{
		secrets: &Secrets{
			secrets: map[string]string{
				"key": "value",
			},
		},
		dicts: &Dictionaries{
			dicts: map[string]*Dictionary{
				"key": {},
			},
		},
	}
	rcv := []byte{
		0x00, 0xff, 0x02, 0x02, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04,
		0x05, 0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
	}
	var synConn syncedConn = &syncedUDPConn{
		connID: "key",
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	srv.handleRcvedBytes(rcv, synConn)
	explog := fmt.Sprintf("error: <%s> when decoding packet\n", "invalid length")
	rcvlog := buf.String()[20:]

	if !reflect.DeepEqual(rcvlog, explog) {
		t.Errorf("\nexpected: <%+v>, \nreceived: <%+v>", explog, rcvlog)
	}
}

func TestServerhandleRcvedBytesNoKey(t *testing.T) {
	srv := &Server{
		secrets: &Secrets{
			secrets: map[string]string{
				"key": "value",
			},
		},
		dicts: &Dictionaries{
			dicts: map[string]*Dictionary{
				"key": {},
			},
		},
	}
	rcv := []byte{
		0x00, 0x03, 0x02, 0x02, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04,
		0x05, 0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
		0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x08, 0x08, 0x08, 0x08,
	}
	var synConn syncedConn = &syncedUDPConn{
		connID: "key",
		addr: &net.UDPAddr{
			IP: net.IP{127, 0, 0, 1},
		},
		pc: &pcMock{
			testcase: "sendReply err",
		},
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	srv.handleRcvedBytes(rcv, synConn)
	time.Sleep((9 * time.Millisecond))
	explog := fmt.Sprintf("error: <no handler for packet with code: %d>", 0)
	rcvlog := buf.String()[20 : 20+len(explog)]

	if !reflect.DeepEqual(rcvlog, explog) {
		t.Errorf("\nexpected: <%+v>, \nreceived: <%+v>", explog, rcvlog)
	}
	explog = "error: <WriteTo error> sending reply\n"
	rcvlog = buf.String()[41+len(rcvlog):]

	if !reflect.DeepEqual(rcvlog, explog) {
		t.Errorf("\nexpected: <%+v>, \nreceived: <%+v>", explog, rcvlog)
	}
}

func TestServerhandleRcvedBytesEmptyHandlerReply(t *testing.T) {
	srv := &Server{
		secrets: &Secrets{
			secrets: map[string]string{
				"key": "value",
			},
		},
		dicts: &Dictionaries{
			dicts: map[string]*Dictionary{
				"key": {},
			},
		},
		reqHandlers: map[PacketCode]func(*Packet) (*Packet, error){
			1: func(p *Packet) (*Packet, error) {
				return nil, nil
			},
		},
	}
	rcv := []byte{
		0x01, 0x03, 0x02, 0x02, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04,
		0x05, 0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
		0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x08, 0x08, 0x08, 0x08,
	}
	var synConn syncedConn = &syncedUDPConn{
		connID: "key",
		addr: &net.UDPAddr{
			IP: net.IP{127, 0, 0, 1},
		},
		pc: &pcMock{
			testcase: "sendReply err",
		},
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	srv.handleRcvedBytes(rcv, synConn)
	time.Sleep(10 * time.Millisecond)
	explog := "warning: empty reply received from handler\n"
	rcvlog := buf.String()[20:]

	if !reflect.DeepEqual(rcvlog, explog) {
		t.Errorf("\nexpected: <%+v>, \nreceived: <%+v>", explog, rcvlog)
	}
}

func TestServerhandleRcvedBytesSendReplyFail(t *testing.T) {
	srv := &Server{
		secrets: &Secrets{
			secrets: map[string]string{
				"key": "value",
			},
		},
		dicts: &Dictionaries{
			dicts: map[string]*Dictionary{
				"key": {},
			},
		},
		reqHandlers: map[PacketCode]func(*Packet) (*Packet, error){
			1: func(p *Packet) (*Packet, error) {
				return nil, fmt.Errorf("hndlr error")
			},
		},
	}
	rcv := []byte{
		0x01, 0x03, 0x02, 0x02, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04,
		0x05, 0x05, 0x05, 0x05, 0x05, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
		0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x08, 0x08, 0x08, 0x08,
	}
	var synConn syncedConn = &syncedUDPConn{
		connID: "key",
		addr: &net.UDPAddr{
			IP: net.IP{127, 0, 0, 1},
		},
		pc: &pcMock{
			testcase: "sendReply err",
		},
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	srv.handleRcvedBytes(rcv, synConn)
	time.Sleep(11 * time.Millisecond)
	explog := fmt.Sprintf("error: <%s> sending reply\n", "WriteTo error")
	rcvlog := buf.String()[20:]

	if !reflect.DeepEqual(rcvlog, explog) {
		t.Errorf("\nexpected: <%+v>, \nreceived: <%+v>", explog, rcvlog)
	}
}

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
	switch cM.testcase {
	case "writeError":
		err = fmt.Errorf("write mock error")
	}
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

func TestServerlistenAndServeTCPDiffErr(t *testing.T) {

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

type pconnMock struct {
	testcase string
	stopChan chan struct{}
}

func (pcM *pconnMock) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	switch pcM.testcase {
	case "ReadFrom error":
		err = fmt.Errorf("packetConn mock error")
		close(pcM.stopChan)
		return 0, nil, err
	}
	return 0, nil, nil
}

func (pcM *pconnMock) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return 0, nil
}

func (pcM *pconnMock) Close() error {
	return nil
}

func (pcM *pconnMock) LocalAddr() net.Addr {
	return nil
}

func (pcM *pconnMock) SetDeadline(t time.Time) error {
	return nil
}

func (pcM *pconnMock) SetReadDeadline(t time.Time) error {
	return nil
}

func (pcM *pconnMock) SetWriteDeadline(t time.Time) error {
	return nil
}

type lnMock struct {
	testcase string
	stopChan chan struct{}
}

func (lM *lnMock) Accept() (net.Conn, error) {
	switch lM.testcase {
	case "listener Accept error":
		err := fmt.Errorf("Accept mock error")
		close(lM.stopChan)
		return nil, err
	}
	return nil, nil
}

func (lM *lnMock) Close() error {
	return nil
}

func (lM *lnMock) Addr() net.Addr {
	return nil
}

func TestServerserveUDPReadFromFail(t *testing.T) {
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

	pc := &pconnMock{
		testcase: "ReadFrom error",
		stopChan: make(chan struct{}),
	}

	experr := "packetConn mock error"
	explog := fmt.Sprintf("error: <%s> when reading packets over udp\n", experr)
	err := srv.serveUDP(pc.stopChan, pc)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	rcv := buf.String()[20:]
	if rcv != explog {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", explog, rcv)
	}
}

func TestServerserveTCPAcceptFail(t *testing.T) {
	srv := &Server{
		addr: "127.0.0.1:1234",
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	ln := &lnMock{
		testcase: "listener Accept error",
		stopChan: make(chan struct{}),
	}

	experr := "Accept mock error"
	explog := fmt.Sprintf("error: <%s>, when establishing new connection\n", experr)
	err := srv.serveTCP(ln.stopChan, ln)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	rcv := buf.String()[20:]
	if rcv != explog {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", explog, rcv)
	}
}
