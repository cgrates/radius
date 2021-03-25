package radigo

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"reflect"
	"sync"
	"testing"

	"github.com/cgrates/radigo/codecs"
)

func TestPacketDecode(t *testing.T) {
	// sample packet taken out of RFC2865 -Section 7.2.
	encdPkt := []byte{
		0x01, 0x01, 0x00, 0x47, 0x2a, 0xee, 0x86, 0xf0, 0x8d, 0x0d, 0x55, 0x96, 0x9c, 0xa5, 0x97, 0x8e,
		0x0d, 0x33, 0x67, 0xa2, 0x01, 0x08, 0x66, 0x6c, 0x6f, 0x70, 0x73, 0x79, 0x03, 0x13, 0x16, 0xe9,
		0x75, 0x57, 0xc3, 0x16, 0x18, 0x58, 0x95, 0xf2, 0x93, 0xff, 0x63, 0x44, 0x07, 0x72, 0x75, 0x04,
		0x06, 0xc0, 0xa8, 0x01, 0x10, 0x05, 0x06, 0x00, 0x00, 0x00, 0x14, 0x06, 0x06, 0x00, 0x00, 0x00,
		0x02, 0x07, 0x06, 0x00, 0x00, 0x00, 0x01, 0x1a, 0x13, 0x00, 0x00, 0x00, 0x09,
		0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67,
	}
	ePkt := &Packet{
		Code:       AccessRequest,
		Identifier: 1,
		Authenticator: [16]byte{0x2a, 0xee, 0x86, 0xf0, 0x8d, 0x0d, 0x55, 0x96, 0x9c, 0xa5, 0x97, 0x8e,
			0x0d, 0x33, 0x67, 0xa2},
		AVPs: []*AVP{
			&AVP{
				Number:   uint8(1),                                   // User-Name
				RawValue: []byte{0x66, 0x6c, 0x6f, 0x70, 0x73, 0x79}, // flopsy
			},
			&AVP{
				Number: uint8(3), // CHAPPassword
				RawValue: []byte{0x16, 0xe9,
					0x75, 0x57, 0xc3, 0x16, 0x18, 0x58, 0x95, 0xf2, 0x93, 0xff, 0x63, 0x44, 0x07, 0x72, 0x75}, // 3
			},
			&AVP{
				Number:   uint8(4),                       // NASIPAddress
				RawValue: []byte{0xc0, 0xa8, 0x01, 0x10}, // 192.168.1.16
			},
			&AVP{
				Number:   uint8(5),                       // NASPort
				RawValue: []byte{0x00, 0x00, 0x00, 0x14}, // 20
			},
			&AVP{
				Number:   uint8(6),                       // ServiceType
				RawValue: []byte{0x00, 0x00, 0x00, 0x02}, // 2
			},
			&AVP{
				Number:   uint8(7),                       // FramedProtocol
				RawValue: []byte{0x00, 0x00, 0x00, 0x01}, // 1
			},
			&AVP{
				Number: VendorSpecificNumber, // VSA
				RawValue: []byte{0x00, 0x00, 0x00, 0x09,
					0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67}, // VendorID: 9(Cisco), VSA-type: 23(Remote-Gateway-ID), VSA-Data: CGRateS.org
			},
		},
	}
	pkt := new(Packet)
	if err := pkt.Decode(encdPkt); err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(ePkt, pkt) {
		t.Errorf("Expecting: %+v, received: %+v", ePkt, pkt)
	}
}

func TestPacketEncode(t *testing.T) {
	pkt := &Packet{
		Code:       AccessAccept,
		Identifier: 1,
		Authenticator: [16]byte{0x2a, 0xee, 0x86, 0xf0, 0x8d, 0x0d, 0x55, 0x96, 0x9c, 0xa5, 0x97, 0x8e,
			0x0d, 0x33, 0x67, 0xa2}, // Authenticator out of origin request
		AVPs: []*AVP{
			&AVP{
				Number:   6,                              // ServiceType
				RawValue: []byte{0x00, 0x00, 0x00, 0x02}, // 2
			},
			&AVP{
				Number:   7,                              // FramedProtocol
				RawValue: []byte{0x00, 0x00, 0x00, 0x01}, // 1
			},
			&AVP{
				Number:   8,                              // FramedIPAddress
				RawValue: []byte{0xff, 0xff, 0xff, 0xfe}, // 255.255.255.254
			},
			&AVP{
				Number:   10,                             // FramedRouting
				RawValue: []byte{0x00, 0x00, 0x00, 0x02}, // 0
			},
			&AVP{
				Number:   13,                             // FramedCompression
				RawValue: []byte{0x00, 0x00, 0x00, 0x01}, // 1
			},
			&AVP{
				Number:   12,                             // FramedMTU
				RawValue: []byte{0x00, 0x00, 0x05, 0xdc}, // 1500
			},
			&AVP{
				Number: 26, // VSA
				RawValue: []byte{0x00, 0x00, 0x00, 0x09,
					0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67}, // VendorID: 9(Cisco), VSA-type: 23(Remote-Gateway-ID), VSA-Data: CGRateS.org
			},
		},
	}
	ePktEncd := []byte{
		0x02, 0x01, 0x00, 0x4b, 0x0c, 0x51, 0xfd, 0x77, 0xec, 0xb6, 0x5a, 0xac, 0x43, 0x8b, 0x79, 0x99,
		0xe4, 0x12, 0x55, 0x18, 0x06, 0x06, 0x00, 0x00, 0x00, 0x02, 0x07, 0x06, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0xff, 0xff, 0xff, 0xfe, 0x0a, 0x06, 0x00, 0x00, 0x00, 0x02, 0x0d, 0x06, 0x00, 0x00,
		0x00, 0x01, 0x0c, 0x06, 0x00, 0x00, 0x05, 0xdc, 0x1a, 0x13, 0x00, 0x00, 0x00, 0x09,
		0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67,
	}
	var buf [4096]byte
	n, err := pkt.Encode(buf[:])
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(ePktEncd, buf[:n]) {
		t.Errorf("Expecting: % x, received: % x", ePktEncd, buf[:n])
	}

}

func TestPacketStringer(t *testing.T) {
	p := AccessRequest
	exp := "AccessRequest"
	if rcv := p.String(); rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}

	p = AccessAccept
	exp = "AccessAccept"
	if rcv := p.String(); rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}

	p = AccessReject
	exp = "AccessReject"
	if rcv := p.String(); rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}

	p = AccountingRequest
	exp = "AccountingRequest"
	if rcv := p.String(); rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}

	p = AccountingResponse
	exp = "AccountingResponse"
	if rcv := p.String(); rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}

	p = AccessChallenge
	exp = "AccessChallenge"
	if rcv := p.String(); rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}

	p = StatusServer
	exp = "StatusServer"
	if rcv := p.String(); rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}

	p = StatusClient
	exp = "StatusClient"
	if rcv := p.String(); rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}

	p = Reserved
	exp = "Reserved"
	if rcv := p.String(); rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}

	p = PacketCode(60)
	exp = "unknown packet code"
	if rcv := p.String(); rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestPacketHas(t *testing.T) {
	p := &Packet{
		AVPs: []*AVP{
			{
				Number: 1,
			},
			{
				Number: 25,
			},
			{
				Number: 5,
			},
		},
	}
	attrNr := uint8(5)

	rcv := p.Has(attrNr)

	if rcv != true {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", true, rcv)
	}
}

func TestPacketHasNot(t *testing.T) {
	p := &Packet{
		AVPs: []*AVP{
			{
				Number: 1,
			},
			{
				Number: 25,
			},
			{
				Number: 5,
			},
		},
	}
	attrNr := uint8(6)

	rcv := p.Has(attrNr)

	if rcv != false {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", false, rcv)
	}
}

func TestPacketNewPacket(t *testing.T) {
	exp := &Packet{
		Code:       Reserved,
		Identifier: uint8(5),
		dict:       &Dictionary{},
		coder:      Coder{},
		secret:     "testString",
	}

	rcv := NewPacket(Reserved, uint8(5), &Dictionary{}, Coder{}, "testString")

	if !reflect.DeepEqual(rcv, exp) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestPacketEncodeNilRawValue(t *testing.T) {
	b := make([]byte, 100)
	p := &Packet{
		RWMutex:       sync.RWMutex{},
		Code:          Reserved,
		Identifier:    uint8(5),
		Authenticator: [16]byte{1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 5, 6},
		AVPs: []*AVP{
			{Number: 0},
			{Number: 1},
		},
	}

	experr := fmt.Sprintf("avp: %+v, no value", p.AVPs[0])
	n, err := p.Encode(b)
	if err == nil || err.Error() != experr {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}

	if n != 0 {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", 0, n)
	}
}

func TestPacketEncodeFailAVPEncode(t *testing.T) {
	b := make([]byte, 100)
	p := &Packet{
		RWMutex:       sync.RWMutex{},
		Code:          Reserved,
		Identifier:    uint8(5),
		Authenticator: [16]byte{1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 5, 6},
		AVPs: []*AVP{
			{
				RawValue: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			},
			{},
		},
	}

	expn := 20
	experr := "value too big for attribute"
	n, err := p.Encode(b)

	if err == nil || err.Error() != experr {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}

	if n != expn {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", expn, n)
	}
}

func TestPacketDecodeInvalidLength(t *testing.T) {
	buf := []byte{0, 255, 1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6}
	p := &Packet{
		RWMutex: sync.RWMutex{},
	}

	experr := "invalid length"
	err := p.Decode(buf)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestPacketDecodeValidationFail(t *testing.T) {
	buf := []byte{0, 1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6, 3, 2, 7}
	p := &Packet{
		RWMutex: sync.RWMutex{},
	}

	expavp := &AVP{
		Number: 3,
	}
	experr := fmt.Sprintf("value too short for : %+v", expavp)
	err := p.Decode(buf)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestPacketNegativeReplyAccess(t *testing.T) {
	errMsg := "testError"
	p := &Packet{
		Code: AccessRequest,
	}

	exp := &Packet{
		Code: AccessReject,
	}
	exp.AVPs = append(exp.AVPs, &AVP{Number: ReplyMessage, RawValue: []byte(errMsg)})
	rcv := p.NegativeReply(errMsg)

	if !reflect.DeepEqual(exp, rcv) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestPacketNegativeReplyAccounting(t *testing.T) {
	errMsg := "testError"
	p := &Packet{
		Code: AccountingRequest,
	}

	exp := &Packet{
		Code: AccountingResponse,
	}
	exp.AVPs = append(exp.AVPs, &AVP{Number: ReplyMessage, RawValue: []byte(errMsg)})
	rcv := p.NegativeReply(errMsg)

	if !reflect.DeepEqual(exp, rcv) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestPacketSetAVPValues(t *testing.T) {
	p := &Packet{
		dict:  &Dictionary{},
		coder: Coder{},
		AVPs: []*AVP{
			{Number: 1},
		},
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)

	p.SetAVPValues()
	t.Logf(buf.String())
}

func TestPacketSetCodeWithName(t *testing.T) {
	p := &Packet{}
	codeName := "Invalid"

	experr := fmt.Sprintf("unsupported packet code name: <%s>", codeName)

	if err := p.SetCodeWithName(codeName); err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}

	codeName = "AccessRequest"

	exp := PacketCode(1)

	if err := p.SetCodeWithName(codeName); err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	} else if p.Code != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, p.Code)
	}

	codeName = "AccessAccept"

	exp = PacketCode(2)

	if err := p.SetCodeWithName(codeName); err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	} else if p.Code != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, p.Code)
	}

	codeName = "AccessReject"

	exp = PacketCode(3)

	if err := p.SetCodeWithName(codeName); err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	} else if p.Code != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, p.Code)
	}

	codeName = "AccountingRequest"

	exp = PacketCode(4)

	if err := p.SetCodeWithName(codeName); err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	} else if p.Code != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, p.Code)
	}

	codeName = "AccountingResponse"

	exp = PacketCode(5)

	if err := p.SetCodeWithName(codeName); err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	} else if p.Code != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, p.Code)
	}

	codeName = "AccessChallenge"

	exp = PacketCode(11)

	if err := p.SetCodeWithName(codeName); err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	} else if p.Code != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, p.Code)
	}

	codeName = "StatusServer"

	exp = PacketCode(12)

	if err := p.SetCodeWithName(codeName); err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	} else if p.Code != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, p.Code)
	}

	codeName = "StatusClient"

	exp = PacketCode(13)

	if err := p.SetCodeWithName(codeName); err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	} else if p.Code != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, p.Code)
	}

	codeName = "Reserved"

	exp = PacketCode(255)

	if err := p.SetCodeWithName(codeName); err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	} else if p.Code != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, p.Code)
	}
}

func TestPacketAttributesWithNameEmptyAttr(t *testing.T) {
	p := &Packet{
		dict: &Dictionary{},
	}

	rcv := p.AttributesWithName("attrName", "vendorName")

	if rcv != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, rcv)
	}
}

func TestPacketAttributesWithNameNilDictVendor(t *testing.T) {
	p := &Packet{
		dict: &Dictionary{
			RWMutex: sync.RWMutex{},
			an: map[string]map[string]*DictionaryAttribute{
				"dictVendorName": {
					"dictAttrName": &DictionaryAttribute{
						AttributeName:   "attrName",
						AttributeNumber: 2,
						AttributeType:   IntegerValue,
					},
				},
			},
		},
	}

	rcv := p.AttributesWithName("dictAttrName", "dictVendorName")

	if rcv != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, rcv)
	}
}

func TestPacketRemoteAddr(t *testing.T) {
	pk := &Packet{
		addr: &net.IPAddr{
			IP: net.IPv4bcast,
		},
	}
	expaddr := net.IPv4bcast.String()
	addr := pk.RemoteAddr()

	if addr.String() != expaddr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", expaddr, addr)
	}

}

func TestPacketAddAVPWithNameDictNotFound(t *testing.T) {
	p := &Packet{
		dict: &Dictionary{},
	}
	attrName := "attrName"
	strVal := "strVal"
	vendorName := "vendorName"

	experr := fmt.Sprintf("DICTIONARY_NOT_FOUND, attributeName: <%s>, vendorName: <%s>", attrName, vendorName)
	err := p.AddAVPWithName(attrName, strVal, vendorName)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestPacketAddAVPWithNameSetRawValueFail(t *testing.T) {
	p := &Packet{
		dict: &Dictionary{
			an: map[string]map[string]*DictionaryAttribute{
				"dictVendor": {
					"dictAttr": &DictionaryAttribute{
						AttributeName:   "attrName",
						AttributeNumber: 2,
						AttributeType:   IntegerValue,
					},
				},
			},
		},
	}

	experr := "unsupported attribute type"
	err := p.AddAVPWithName("dictAttr", "strVal", "dictVendor")

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestPacketAddAVPWithNumberDictNotFound(t *testing.T) {
	p := &Packet{
		dict: &Dictionary{},
	}
	var attrNr uint8
	var val interface{}
	var vendorCode uint32

	experr := fmt.Sprintf("DICTIONARY_NOT_FOUND, item %d, vendor: %d", attrNr, vendorCode)
	err := p.AddAVPWithNumber(attrNr, val, vendorCode)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestPacketAddAVPWithNumberSetRawValueFail(t *testing.T) {
	p := &Packet{
		dict: &Dictionary{
			ac: map[uint32]map[uint8]*DictionaryAttribute{
				NoVendor: {
					5: &DictionaryAttribute{
						AttributeName:   "attrName",
						AttributeNumber: 2,
						AttributeType:   IntegerValue,
					},
				},
			},
		},
	}
	attrNr := uint8(5)
	var val interface{} = 8
	vendorCode := uint32(0)

	experr := "unsupported attribute type"
	err := p.AddAVPWithNumber(attrNr, val, vendorCode)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestPacketAddAVPWithNumberSuccess(t *testing.T) {
	p := &Packet{
		dict: &Dictionary{
			ac: map[uint32]map[uint8]*DictionaryAttribute{
				1: {
					5: &DictionaryAttribute{
						AttributeName:   "attrName",
						AttributeNumber: 2,
						AttributeType:   IntegerValue,
					},
				},
			},
		},
		coder: Coder{
			IntegerValue: codecs.IntegerCodec{},
		},
	}
	attrNr := uint8(5)
	var val interface{} = uint32(8)
	vendorCode := uint32(1)
	explen := len(p.AVPs) + 1
	expp := &Packet{
		dict: &Dictionary{
			ac: map[uint32]map[uint8]*DictionaryAttribute{
				1: {
					5: &DictionaryAttribute{
						AttributeName:   "attrName",
						AttributeNumber: 2,
						AttributeType:   IntegerValue,
					},
				},
			},
		},
		coder: Coder{
			IntegerValue: codecs.IntegerCodec{},
		},
		AVPs: []*AVP{
			{
				Number:   26,
				Name:     VendorSpecificName,
				Type:     StringValue,
				RawValue: []byte{0, 0, 0, 1, 5, 6, 0, 0, 0, 8},
				Value: &VSA{
					Vendor:   1,
					Number:   5,
					Name:     "attrName",
					Type:     IntegerValue,
					Value:    uint32(8),
					RawValue: []byte{0, 0, 0, 8},
				},
			},
		},
	}
	err := p.AddAVPWithNumber(attrNr, val, vendorCode)

	if err != nil {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !reflect.DeepEqual(expp.AVPs[explen-1].Value, p.AVPs[explen-1].Value) {
		t.Fatalf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			expp.AVPs[explen-1].Value,
			p.AVPs[explen-1].Value,
		)
	}

	if p.AVPs[explen-1].Name != expp.AVPs[explen-1].Name {
		t.Fatalf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			expp.AVPs[explen-1].Name,
			p.AVPs[explen-1].Name,
		)
	}

	if p.AVPs[explen-1].Type != expp.AVPs[explen-1].Type {
		t.Fatalf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			expp.AVPs[explen-1].Type,
			p.AVPs[explen-1].Type,
		)
	}

	if p.AVPs[explen-1].Number != expp.AVPs[explen-1].Number {
		t.Fatalf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			expp.AVPs[explen-1].Number,
			p.AVPs[explen-1].Number,
		)
	}

	if string(p.AVPs[explen-1].RawValue) != string(expp.AVPs[explen-1].RawValue) {
		t.Fatalf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			expp.AVPs[explen-1].Value,
			p.AVPs[explen-1].Value,
		)
	}

	if len(p.AVPs) != explen {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", explen, len(p.AVPs))
	}
}

func TestPacketAttributesWithNumber1(t *testing.T) {
	p := &Packet{
		dict:  &Dictionary{},
		coder: Coder{},
		AVPs: []*AVP{
			{
				Number: 1,
			},
			{},
		},
	}
	_ = p.AttributesWithNumber(1, NoVendor)
}

func TestPacketAttributesWithNumber2(t *testing.T) {
	p := &Packet{
		dict:  &Dictionary{},
		coder: Coder{},
		AVPs: []*AVP{
			{
				Number:   VendorSpecificNumber,
				RawValue: []byte{1, 2, 2, 3, 3, 3, 4, 4, 4, 4},
				Value:    &VSA{},
			},
		},
	}
	_ = p.AttributesWithNumber(1, 2)
}

func TestPacket123(t *testing.T) {
	p := &Packet{
		dict: &Dictionary{
			ac: map[uint32]map[uint8]*DictionaryAttribute{
				9: {
					23: &DictionaryAttribute{
						AttributeName:   "attrName",
						AttributeNumber: 2,
						AttributeType:   IntegerValue,
					},
				},
			},
		},
		coder: Coder{
			IntegerValue: codecs.IntegerCodec{},
		},
		AVPs: []*AVP{
			{
				Number: 26,
				RawValue: []byte{0x00, 0x00, 0x00, 0x09,
					0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67},
			},
		},
	}

	_ = p.AttributesWithNumber(1, 2)

}
