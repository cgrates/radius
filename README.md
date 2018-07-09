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
	. "github.com/cgrates/radigo"
	"log"
	"strings"
)

	var sampleDict =`
## Sample dictionary file containing few lines of Cisco vendor

# Vendors
VENDOR    Cisco    9

BEGIN-VENDOR    Cisco
ATTRIBUTE       Cisco-AVPair    1   string
ATTRIBUTE       Cisco-NAS-Port  2	string
END-VENDOR      Cisco
`

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
	dict := RFC2865Dictionary()

	if err := dict.ParseFromReader(strings.NewReader(sampleDict)); err != nil {
		log.Fatalln(err)
	}

	secrets := NewSecrets(map[string]string{"127.0.0.1": "CGRateS.org"})
	dicts := NewDictionaries(map[string]*Dictionary{"127.0.0.1": dict})

	// Start RADIUS AUTH Server
	go NewServer("tcp", "localhost:1812",
		secrets, dicts,
		map[PacketCode]func(*Packet) (*Packet, error){AccessRequest: handleAuth}, nil).ListenAndServe()

	// Start RADIUS ACCT Server
	go NewServer("tcp", "localhost:1813",
		secrets, dicts,
		map[PacketCode]func(*Packet) (*Packet, error){AccountingRequest: handleAcct}, nil).ListenAndServe()

	// Connect Auth client:
	authClnt, err := NewClient("tcp", "localhost:1812", "CGRateS.org", dict, 0, nil)
	if err != nil {
		log.Fatalf("Could not connect to RAD-AUTH server, error: %s", err.Error())
	}

	req := authClnt.NewRequest(AccessRequest, 1)
	if err := req.AddAVPWithName("User-Name", "flopsy", ""); err != nil {
		log.Fatalln(err)
	}
	if err := req.AddAVPWithName("Cisco-NAS-Port", "CGR1", "Cisco"); err != nil {
		log.Fatalln(err)
	}
	if reply, err := authClnt.SendRequest(req); err != nil {
		log.Println(err)
	} else {
		log.Printf("Received reply: %+v", reply.Code)
	}
}


```
[![Build Status](https://secure.travis-ci.org/cgrates/radigo.png)](http://travis-ci.org/cgrates/radigo)
