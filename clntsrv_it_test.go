// +build integration

/*
Integration tests between radigo client and server
*/
package radigo

import (
	"strings"
	"testing"
)

var (
	dict *Dictionary
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
	go NewServer("tcp", "localhost:1812",
		map[string]string{"127.0.0.1": "CGRateS.org"},
		map[string]*Dictionary{"127.0.0.1": RFC2865Dictionary()},
		map[PacketCode]func(*Packet) (*Packet, error){AccessRequest: handleAuth}, nil).ListenAndServe()
	go NewServer("tcp", "localhost:1813",
		map[string]string{"127.0.0.1": "CGRateS.org"},
		map[string]*Dictionary{"127.0.0.1": RFC2865Dictionary()},
		map[PacketCode]func(*Packet) (*Packet, error){AccountingRequest: handleAcct}, nil).ListenAndServe()
}

func TestRadClientAuth(t *testing.T) {
	authClnt, err := NewClient("tcp", "localhost:1812", "CGRateS.org", dict, 0, nil)
	if err != nil {
		t.Error(err)
	}
	req := &Packet{
		Code:       AccessRequest,
		Identifier: 1,
		dict:       dict,
		coder:      NewCoder(),
	}
	if err := req.AddAVPWithName("User-Name", "flopsy", ""); err != nil {
		t.Error(err)
	}
	if err := req.AddAVPWithName("Cisco-NAS-Port", "CGR1", "Cisco"); err != nil {
		t.Error(err)
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

func TestRadClientAccount(t *testing.T) {
	req := &Packet{
		Code:       AccountingRequest,
		Identifier: 2,
		dict:       dict,
		coder:      NewCoder(),
	}
	if err := req.AddAVPWithName("User-Name", "flopsy", ""); err != nil {
		t.Error(err)
	}
	if err := req.AddAVPWithName("Cisco-NAS-Port", "CGR1", "Cisco"); err != nil {
		t.Error(err)
	}
	acntClnt, err := NewClient("tcp", "localhost:1813", "CGRateS.org", dict, 0, nil)
	if err != nil {
		t.Error(err)
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
