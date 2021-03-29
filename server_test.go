package radigo

import (
	"net"
	"reflect"
	"testing"
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
