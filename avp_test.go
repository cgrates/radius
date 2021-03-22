package radigo

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestVSAToAVP(t *testing.T) {
	vsa := &VSA{
		Vendor:   9,
		Number:   23,
		RawValue: []byte("CGRateS.org"),
	}
	eAVP := &AVP{
		Number: VendorSpecificNumber,
		RawValue: []byte{0x00, 0x00, 0x00, 0x09,
			0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67},
	}
	if avp := vsa.AVP(); !reflect.DeepEqual(eAVP, avp) {
		t.Errorf("Expecting: %+v, received: %+v", eAVP, avp)
	}
}

func TestNewVSAFromAVP(t *testing.T) {
	avp := &AVP{
		Number: VendorSpecificNumber,
		RawValue: []byte{0x00, 0x00, 0x00, 0x09,
			0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67},
	}
	eVsa := &VSA{
		Vendor:   9,
		Number:   23,
		RawValue: []byte("CGRateS.org"),
	}
	if vsa, err := NewVSAFromAVP(avp); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(eVsa, vsa) {
		t.Errorf("Expecting: %+v, received: %+v", eVsa, vsa)
	}
}

func TestAVPSetValue(t *testing.T) {
	avp := &AVP{
		Number:   uint8(4),                       // NASIPAddress
		RawValue: []byte{0xc0, 0xa8, 0x01, 0x10}, // 192.168.1.16
	}
	eAvp := &AVP{
		Number:   avp.Number,   // NASIPAddress
		RawValue: avp.RawValue, // 192.168.1.16
		Name:     "NAS-IP-Address",
		Type:     AddressValue,
		Value:    net.IP(avp.RawValue),
	}
	if err := avp.SetValue(RFC2865Dictionary(), NewCoder()); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(eAvp.Value, avp.Value) {
		t.Errorf("Expecting: %+v, received: %+v", eAvp, avp)
	}
}

func TestAVPSetRawValueWithAlias(t *testing.T) {
	dictAliasSample := `
# Alias values
VALUE    Framed-Protocol    PPP    1
`
	d := RFC2865Dictionary()
	d.ParseFromReader(strings.NewReader(dictAliasSample))
	avp := &AVP{Name: "Framed-Protocol", Type: IntegerValue, StringValue: "PPP"}
	if err := avp.SetRawValue(d, NewCoder()); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(avp.RawValue, []byte{0x0, 0x0, 0x0, 0x01}) {
		t.Errorf("Received: %x", avp.RawValue)
	}
}

func TestEncodeDecodeUserPassword(t *testing.T) {
	pkt := &Packet{
		secret: "CGRateS.org",
		Authenticator: [16]byte{0x2a, 0xee, 0x86, 0xf0, 0x8d, 0x0d, 0x55, 0x96, 0x9c, 0xa5, 0x97, 0x8e,
			0x0d, 0x33, 0x67, 0xa2},
	}
	pass := "CGRateSPassword1"
	encd := EncodeUserPassWord([]byte(pass), []byte(pkt.secret), pkt.Authenticator[:])
	avp := &AVP{RawValue: encd}
	if err := DecodeUserPassword(pkt, avp); err != nil {
		t.Error(err)
	}
	if string(avp.RawValue) != pass {
		t.Errorf("Expected <%q> received <%q>", pass, string(avp.RawValue))
	}
}

func TestAVPEncode(t *testing.T) {
	a := &AVP{
		RawValue: []byte("test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test test"),
	}
	b := make([]byte, 255)
	experr := "value too big for attribute"
	rcv, err := a.Encode(b)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}

	if rcv != 0 {
		t.Errorf("\nExpected 0, \nReceived: <%+v>", rcv)
	}
}

func TestAVPGetStringValueNonVendorNr(t *testing.T) {
	a := &AVP{
		Number:      1,
		StringValue: "testString",
	}

	exp := "testString"
	rcv := a.GetStringValue()

	if exp != rcv {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestAVPGetStringValueVendorSpecificNr(t *testing.T) {
	a := &AVP{
		Number:      VendorSpecificNumber,
		StringValue: "testString",
		Value: &VSA{
			StringValue: "test",
		},
	}

	exp := "test"
	rcv := a.GetStringValue()

	if exp != rcv {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestAVPSetValueExists(t *testing.T) {
	a := &AVP{
		Value: &VSA{},
	}
	dict := &Dictionary{}
	var cdr Coder

	err := a.SetValue(dict, cdr)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}
}

func TestAVPSetValueNoData(t *testing.T) {
	a := &AVP{
		Number: 1,
	}
	dict := &Dictionary{}
	var cdr Coder

	experr := fmt.Sprintf("no dictionary data for avp: %+v", a)
	err := a.SetValue(dict, cdr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

// func TestAVPSetValue1(t *testing.T) {
// 	a := &AVP{
// 		Number:   1,
// 		Name:     "name",
// 		RawValue: []byte{0x00, 0x00, 0x00, 0x09, 0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67},
// 	}
// 	dict := &Dictionary{
// 		valNr: map[uint32]map[string]map[uint8]*DictionaryValue{
// 			1: {
// 				"key": {
// 					1: &DictionaryValue{
// 						AttributeName: "attrName",
// 						ValueName:     "valName",
// 						ValueNumber:   10,
// 					},
// 				},
// 			},
// 		},
// 		RWMutex: sync.RWMutex{},
// 		ac: map[uint32]map[uint8]*DictionaryAttribute{
// 			NoVendor: {
// 				1: &DictionaryAttribute{
// 					AttributeName:   "testName",
// 					AttributeNumber: 2,
// 					AttributeType:   IntegerValue,
// 				},
// 			},
// 		},
// 	}
// 	cdr := Coder{
// 		IntegerValue: codecs.IntegerCodec{},
// 	}

// 	experr := fmt.Sprintf("no dictionary data for avp: %+v", a)
// 	err := a.SetValue(dict, cdr)

// 	if err == nil || err.Error() != experr {
// 		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
// 	}
// }

type coderMock struct {
	err error
}

func (cM *coderMock) Decode([]byte) (interface{}, string, error) {
	cM.err = fmt.Errorf("error")
	return nil, "", cM.err
}
func (cM *coderMock) Encode(interface{}) ([]byte, error) {
	return nil, nil
}
func (cM *coderMock) EncodeString(string) ([]byte, error) {
	return nil, nil
}

func TestAVPSetValue2(t *testing.T) {
	a := &AVP{
		Number:   1,
		Name:     "name",
		RawValue: []byte{0x00, 0x00, 0x00, 0x09, 0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67},
	}
	dict := &Dictionary{
		RWMutex: sync.RWMutex{},
		ac: map[uint32]map[uint8]*DictionaryAttribute{
			NoVendor: {
				1: &DictionaryAttribute{
					AttributeName:   "testName",
					AttributeNumber: 2,
					AttributeType:   "testType",
				},
			},
		},
	}
	cdr := Coder{
		"testType": &coderMock{},
	}

	experr := "error"
	err := a.SetValue(dict, cdr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestAVPNewVSAFromAVP(t *testing.T) {
	avp := &AVP{
		Number: 1,
	}

	experr := "not VSA type"
	rcv, err := NewVSAFromAVP(avp)

	if err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}

	if rcv != nil {
		t.Errorf("\nExpected nil, \nReceived: <%+v>", rcv)
	}
}
