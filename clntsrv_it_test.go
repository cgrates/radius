// +build integration

/*
Integration tests between radigo client and server
*/
package radigo

import (
	"testing"
)

var (
	dict *Dictionary
)

func handleAuth(req *Packet) (rpl *Packet, err error) {
	rpl = req.Reply()
	rpl.Code = AccessAccept
	return
}

func handleAcct(req *Packet) (rpl *Packet, err error) {
	rpl = req.Reply()
	rpl.Code = AccountingResponse
	return
}

func init() {
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
		map[PacketCode]func(*Packet) (*Packet, error){AccessRequest: handleAuth}).ListenAndServe()
	go NewServer("tcp", "localhost:1813",
		map[string]string{"127.0.0.1": "CGRateS.org"},
		map[string]*Dictionary{"127.0.0.1": RFC2865Dictionary()},
		map[PacketCode]func(*Packet) (*Packet, error){AccountingRequest: handleAcct}).ListenAndServe()
}

func TestRadClientAuth(t *testing.T) {
	authClnt, err := NewClient("tcp", "localhost:1812", "CGRateS.org", RFC2865Dictionary(), 0)
	if err != nil {
		t.Error(err)
	}
	req := &Packet{
		Code:       AccessRequest,
		Identifier: 1,
		AVPs: []*AVP{
			&AVP{
				Name:  "User-Name",
				Value: "flopsy",
			},
		},
	}
	if reply, err := authClnt.SendRequest(req); err != nil {
		t.Error(err)
	} else if reply.Code != AccessAccept {
		t.Errorf("Received reply: %+v", reply)
	}
}

func TestRadClientAccount(t *testing.T) {
	req := &Packet{
		Code:       AccountingRequest,
		Identifier: 2,
		AVPs: []*AVP{
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
		},
	}
	acntClnt, err := NewClient("tcp", "localhost:1813", "CGRateS.org", RFC2865Dictionary(), 0)
	if err != nil {
		t.Error(err)
	}
	if reply, err := acntClnt.SendRequest(req); err != nil {
		t.Error(err)
	} else if reply.Code != AccountingResponse {
		t.Errorf("Received reply: %+v", reply)
	}
}
