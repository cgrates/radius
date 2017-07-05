# RADiGo

RADIUS library for Go language. 

Provides both Client and Server functionality, both asynchronous and thread safe.

Support for both UDP and TCP as transports.

Support for Vendor Specific Attributes.

Support for client based secret and dictionaries.


## Sample usage code ##
```
package main

import (
	"log"
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


func main() {
	// Centralized secrets and dictionaries
	secrets := NewSecrets(map[string]string{"127.0.0.1": "CGRateS.org"})
	dicts := NewDictionaries(map[string]*Dictionary{"127.0.0.1": RFC2865Dictionary()})

	// Start RADIUS AUTH Server
	go NewServer("tcp", "localhost:1812",
		secrets, dicts,
		map[PacketCode]func(*Packet) (*Packet, error){AccessRequest: handleAuth}).ListenAndServe()

	// Start RADIUS ACCT Server
	go NewServer("tcp", "localhost:1813",
		secrets, dicts,
		map[PacketCode]func(*Packet) (*Packet, error){AccountingRequest: handleAcct}).ListenAndServe()

	// Connect Auth client:
	authClnt, err := NewClient("tcp", "localhost:1812", "CGRateS.org", RFC2865Dictionary(), 0)
	if err != nil {
		log.Fatalf("Could not connect to RAD-AUTH server, error: %s", err.Error())
	}

	// Send request
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
	if reply, err := authClnt.SendRequest(req); err != nil {
		t.Error(err)
	} else if reply.Code != AccessAccept {
		t.Errorf("Received reply: %+v", reply)
	}
}


```

