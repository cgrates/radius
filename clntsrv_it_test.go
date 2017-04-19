// +build integration

/*
Integration tests between radigo client and server
*/
package radigo

import (
	"testing"
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
		Authenticator: [16]byte{0x2a, 0xee, 0x86, 0xf0, 0x8d, 0x0d, 0x55, 0x96, 0x9c, 0xa5, 0x97, 0x8e,
			0x0d, 0x33, 0x67, 0xa2},
		AVPs: []*AVP{
			&AVP{
				Number:   uint8(1),                                   // User-Name
				RawValue: []byte{0x66, 0x6c, 0x6f, 0x70, 0x73, 0x79}, // flopsy
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
		Authenticator: [16]byte{0x2a, 0xee, 0x86, 0xf0, 0x8d, 0x0d, 0x55, 0x96, 0x9c, 0xa5, 0x97, 0x8e,
			0x0d, 0x33, 0x67, 0xa2},
		AVPs: []*AVP{
			&AVP{
				Number:   uint8(1),                                   // User-Name
				RawValue: []byte{0x66, 0x6c, 0x6f, 0x70, 0x73, 0x79}, // flopsy
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
