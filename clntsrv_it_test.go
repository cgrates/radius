// +build integration

/*
Integration tests between radigo client and server
*/
package radigo

import (
	"strings"
	"testing"
	"time"
	//"fmt"
)

var (
	dict    *Dictionary
	testNet string
)

func handleAuth(req *Packet) (rpl *Packet, err error) {
	rpl = req.Reply()
	for _, avp := range req.AVPs {
		rpl.AVPs = append(rpl.AVPs, avp)
	}
	rpl.Code = AccessAccept
	return
}

func handleAcct(req *Packet) (rpl *Packet, err error) {
	rpl = req.Reply()
	for _, avp := range req.AVPs {
		rpl.AVPs = append(rpl.AVPs, avp)
	}
	rpl.Code = AccountingResponse
	return
}

var radSTestsIT = []func(t *testing.T){
	testRadClientAuth,
	testRadClientAccount,
}

func testRadClientAuth(t *testing.T) {
	authClnt, err := NewClient(testNet, "127.0.0.1:1812", "CGRateS.org", dict, 0)
	if err != nil {
		t.Fatal(err)
	}
	req := &Packet{
		Code:       AccessRequest,
		Identifier: 1,
		AVPs: []*AVP{
			&AVP{
				Name:  "User-Name",
				Value: "flopsy",
			},
			&AVP{
				Number: VendorSpecific,
				Value: &VSA{
					VendorName: "Cisco",
					Name:       "Cisco-NAS-Port",
					Value:      "CGR1",
				},
			},
		},
	}
	reply, err := authClnt.SendRequest(req)
	if err != nil {
		t.Error(err)
	}
	if reply.Code != AccessAccept {
		t.Errorf("Received reply: %+v", reply)
	}
	if len(reply.AVPs) != len(req.AVPs) {
		t.Errorf("Expecting: %+v, received: %+v", req.AVPs, reply.AVPs)
	}
	if avps := reply.AttributesWithName("User-Name", ""); len(avps) != 1 {
		t.Errorf("Unexpected AVPs: %+v", avps)
	} else if req.AVPs[0].Name != avps[0].Name {
		t.Errorf("Expecting: %+v, received: %+v", req.AVPs[0].Name, avps[0].Name)
	}
	if avps := reply.AttributesWithName("Cisco-NAS-Port", "Cisco"); len(avps) != 1 {
		t.Errorf("Unexpected AVPs: %+v", avps)
	} else if req.AVPs[1].Name != avps[0].Name {
		t.Errorf("Expecting: %+v, received: %+v", req.AVPs[1].Name, avps[0].Name)
	}
}

func testRadClientAccount(t *testing.T) {
	req := &Packet{
		Code:       AccountingRequest,
		Identifier: 2,
		AVPs: []*AVP{
			&AVP{
				Name:  "User-Name",
				Value: "flopsy",
			},
			&AVP{
				Number: VendorSpecific,
				Value: &VSA{
					VendorName: "Cisco",
					Name:       "Cisco-NAS-Port",
					Value:      "CGR1",
				},
			},
		},
	}
	acntClnt, err := NewClient(testNet, "127.0.0.1:1813", "CGRateS.org", dict, 0)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := acntClnt.SendRequest(req)
	if err != nil {
		t.Error(err)
	}
	if reply.Code != AccountingResponse {
		t.Errorf("Received reply: %+v", reply)
	}
	if len(reply.AVPs) != len(req.AVPs) {
		t.Errorf("Expecting: %+v, received: %+v", req.AVPs, reply.AVPs)
	}
}

func TestRadServerStart(t *testing.T) {
	freeRADIUSDocDictSample := `
# Most of the lines are copied from freeradius documentation here:
# http://networkradius.com/doc/3.0.10/concepts/dictionary/introduction.html

# Attributes
ATTRIBUTE    User-Name    1    string
ATTRIBUTE    Password     2    string

# Alias values
VALUE    Framed-Protocol    PPP    1

# Vendors
VENDOR    Cisco    9
VENDOR    Microsoft 311

# Vendor AVPs
BEGIN-VENDOR    Cisco
ATTRIBUTE       Cisco-AVPair    1   string
ATTRIBUTE       Cisco-NAS-Port  2	string
END-VENDOR      Cisco
`
	dict = RFC2865Dictionary()
	// Load some VSA for our tests
	if err := dict.parseFromReader(strings.NewReader(freeRADIUSDocDictSample)); err != nil {
		t.Error(err)
	}
	go NewServer("udp", "localhost:1812",
		map[string]string{"127.0.0.1": "CGRateS.org"},
		map[string]*Dictionary{"127.0.0.1": RFC2865Dictionary()},
		map[PacketCode]func(*Packet) (*Packet, error){AccessRequest: handleAuth}).ListenAndServe()
	go NewServer("udp", "localhost:1813",
		map[string]string{"127.0.0.1": "CGRateS.org"},
		map[string]*Dictionary{"127.0.0.1": RFC2865Dictionary()},
		map[PacketCode]func(*Packet) (*Packet, error){AccountingRequest: handleAcct}).ListenAndServe()
	go NewServer("tcp", "localhost:1812",
		map[string]string{"127.0.0.1": "CGRateS.org"},
		map[string]*Dictionary{"127.0.0.1": RFC2865Dictionary()},
		map[PacketCode]func(*Packet) (*Packet, error){AccessRequest: handleAuth}).ListenAndServe()
	go NewServer("tcp", "localhost:1813",
		map[string]string{"127.0.0.1": "CGRateS.org"},
		map[string]*Dictionary{"127.0.0.1": RFC2865Dictionary()},
		map[PacketCode]func(*Packet) (*Packet, error){AccountingRequest: handleAcct}).ListenAndServe()
	time.Sleep(1 * time.Millisecond)
}

func TestRadClientUDP(t *testing.T) {
	testNet = "udp"
	for _, stest := range radSTestsIT {
		t.Run("TestRadClientUDP", stest)
	}
}

func TestRadClientTCP(t *testing.T) {
	testNet = "tcp"
	for _, stest := range radSTestsIT {
		t.Run("TestRadClientTCP", stest)
	}
}
