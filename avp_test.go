package radigo

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/cgrates/radigo/codecs"
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
	encd := EncodeUserPassword([]byte(pass), []byte(pkt.secret), pkt.Authenticator[:])
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

func TestAVPSetValueInteger(t *testing.T) {
	a := &AVP{
		Number:   1,
		Name:     VendorSpecificName,
		RawValue: []byte{0x00, 0x00, 0x00, 0x09, 0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67},
	}
	dict := &Dictionary{
		valNr: map[uint32]map[string]map[uint8]*DictionaryValue{
			NoVendor: {
				"testName": {
					uint8(9): &DictionaryValue{
						AttributeName: "attrName",
						ValueName:     "valName",
						ValueNumber:   10,
					},
				},
			},
		},
		RWMutex: sync.RWMutex{},
		ac: map[uint32]map[uint8]*DictionaryAttribute{
			NoVendor: {
				1: &DictionaryAttribute{
					AttributeName:   "testName",
					AttributeNumber: 2,
					AttributeType:   IntegerValue,
				},
			},
		},
	}
	cdr := Coder{
		IntegerValue: codecs.IntegerCodec{},
	}

	err := a.SetValue(dict, cdr)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

}

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

func TestAVPSetValueDecodeFail(t *testing.T) {
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

func TestAVPSetValueUnsupportedAttribute(t *testing.T) {
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
	var cdr Coder

	err := a.SetValue(dict, cdr)

	if err != nil {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if a.Value != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, a.Value)
	}
}

func TestAVPSetValueVSA(t *testing.T) {
	a := &AVP{
		Number:   VendorSpecificNumber,
		RawValue: []byte{0x00, 0x00, 0x00, 0x09, 0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67},
	}

	dict := &Dictionary{}
	var cdr Coder

	experr := fmt.Sprintf("DICTIONARY_NOT_FOUND, attribute: <%d>, vendor: <%d>", 23, 9)
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
		t.Errorf("\nExpected nil, \nReceived: %+v", rcv)
	}
}

func TestAVPSetRawValueNonEmptyRawValue(t *testing.T) {
	a := &AVP{
		RawValue: []byte("not empty"),
	}
	var dict *Dictionary
	var cdr Coder

	err := a.SetRawValue(dict, cdr)

	if err != nil {
		t.Errorf("\nExpected nil, \nReceived: %+v", err)
	}
}

func TestAVPSetRawValueEmptyValues(t *testing.T) {
	a := &AVP{}
	var dict *Dictionary
	var cdr Coder

	experr := fmt.Sprintf("avp: %+v, no value", a)
	err := a.SetRawValue(dict, cdr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestAVPSetRawValueEmptyDictAttr(t *testing.T) {
	a := &AVP{
		Name:   "name",
		Number: 1,
		Value: &VSA{
			StringValue: "test",
		},
		StringValue: "testString",
	}

	dict := &Dictionary{}
	var cdr Coder

	experr := fmt.Sprintf("%+v, missing dictionary data", a)
	err := a.SetRawValue(dict, cdr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestAVPSetRawValueVSACastFail(t *testing.T) {
	a := &AVP{
		Name:        "",
		Number:      VendorSpecificNumber,
		StringValue: "testString",
	}
	dict := &Dictionary{
		ac: map[uint32]map[uint8]*DictionaryAttribute{
			NoVendor: {
				VendorSpecificNumber: &DictionaryAttribute{
					AttributeName:   "testName",
					AttributeNumber: VendorSpecificNumber,
					AttributeType:   IntegerValue,
				},
			},
		},
	}

	var cdr Coder

	exp := &AVP{
		Name:        "testName",
		Number:      VendorSpecificNumber,
		StringValue: "testString",
		Type:        "integer",
	}
	experr := fmt.Sprintf("%+v, cannot cast to VSA", exp)
	err := a.SetRawValue(dict, cdr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestAVPSetRawValueEmptyVSA(t *testing.T) {
	a := &AVP{
		Name:        "",
		Number:      VendorSpecificNumber,
		StringValue: "testString",
		Value: &VSA{
			Value:       nil,
			StringValue: "",
		},
	}
	dict := &Dictionary{
		ac: map[uint32]map[uint8]*DictionaryAttribute{
			NoVendor: {
				VendorSpecificNumber: &DictionaryAttribute{
					AttributeName:   "testName",
					AttributeNumber: VendorSpecificNumber,
					AttributeType:   IntegerValue,
				},
			},
		},
	}

	var cdr Coder

	experr := fmt.Sprintf("no value in VSA: %+v", a.Value)
	err := a.SetRawValue(dict, cdr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestAVPSetRawValueUnsupportedAttribute1(t *testing.T) {
	a := &AVP{
		Name:        "",
		Type:        IntegerValue,
		Number:      1,
		StringValue: "testString",
		Value: &VSA{
			Value:       nil,
			StringValue: "",
		},
	}

	dict := &Dictionary{
		ac: map[uint32]map[uint8]*DictionaryAttribute{
			NoVendor: {
				VendorSpecificNumber: &DictionaryAttribute{
					AttributeName:   "testName",
					AttributeNumber: VendorSpecificNumber,
					AttributeType:   IntegerValue,
				},
			},
		},
	}

	var cdr Coder

	experr := "unsupported attribute type"
	err := a.SetRawValue(dict, cdr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestAVPSetRawValueUnsupportedAttribute2(t *testing.T) {
	a := &AVP{
		Name:        "",
		Type:        IntegerValue,
		Number:      1,
		StringValue: "testString",
	}
	dict := &Dictionary{
		ac: map[uint32]map[uint8]*DictionaryAttribute{
			NoVendor: {
				VendorSpecificNumber: &DictionaryAttribute{
					AttributeName:   "testName",
					AttributeNumber: VendorSpecificNumber,
					AttributeType:   IntegerValue,
				},
			},
		},
	}

	var cdr Coder

	experr := "unsupported attribute type"
	err := a.SetRawValue(dict, cdr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestAVPVSASetValueExists(t *testing.T) {
	vsa := &VSA{
		Value: "not empty",
	}

	var dict *Dictionary
	var cdr Coder

	err := vsa.SetValue(dict, cdr)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}
}

func TestAVPVSASetValueUnsupportedAttribute1(t *testing.T) {
	vsa := &VSA{
		Number: VendorSpecificNumber,
		Vendor: NoVendor,
	}

	dict := &Dictionary{
		ac: map[uint32]map[uint8]*DictionaryAttribute{
			NoVendor: {
				VendorSpecificNumber: &DictionaryAttribute{
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
	err := vsa.SetValue(dict, cdr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestAVPVSASetValueUnsupportedAttribute2(t *testing.T) {
	vsa := &VSA{
		Number: VendorSpecificNumber,
		Vendor: NoVendor,
	}

	dict := &Dictionary{
		ac: map[uint32]map[uint8]*DictionaryAttribute{
			NoVendor: {
				VendorSpecificNumber: &DictionaryAttribute{
					AttributeName:   "testName",
					AttributeNumber: 2,
					AttributeType:   "testType",
				},
			},
		},
	}

	cdr := Coder{
		IntegerValue: codecs.IntegerCodec{},
	}

	err := vsa.SetValue(dict, cdr)

	if err != nil {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if vsa.Value != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, vsa.Value)
	}
}

func TestAVPVSASetValueTypeInteger(t *testing.T) {
	vsa := &VSA{
		Number:   VendorSpecificNumber,
		Type:     IntegerValue,
		Vendor:   NoVendor,
		RawValue: []byte{0x00, 0x00, 0x00, 0x09, 0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67},
	}

	dict := &Dictionary{
		valNr: map[uint32]map[string]map[uint8]*DictionaryValue{
			NoVendor: {
				"testName": {
					9: &DictionaryValue{
						AttributeName: "testName",
						ValueName:     "testValue",
						ValueNumber:   2,
					},
				},
			},
		},
		ac: map[uint32]map[uint8]*DictionaryAttribute{
			NoVendor: {
				VendorSpecificNumber: &DictionaryAttribute{
					AttributeName:   "testName",
					AttributeNumber: 2,
					AttributeType:   IntegerValue,
				},
			},
		},
	}

	cdr := Coder{
		IntegerValue: codecs.IntegerCodec{},
	}

	var expval interface{} = uint32(9)
	err := vsa.SetValue(dict, cdr)

	if err != nil {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if expval != vsa.Value {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", expval, vsa.Value)
	}
}

func TestAVPVSASetRawValueExists(t *testing.T) {
	vsa := &VSA{
		RawValue: []byte("not empty"),
	}

	var dict *Dictionary
	var cdr Coder

	err := vsa.SetRawValue(dict, cdr)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}
}

func TestAVPVSASetRawValueNoType(t *testing.T) {
	vsa := &VSA{
		StringValue: "testString",
		Name:        "testName",
	}

	dict := &Dictionary{}
	cdr := Coder{}

	experr := fmt.Sprintf("no vendor in dictionary for VSA: %+v, ", vsa)
	err := vsa.SetRawValue(dict, cdr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestAVPVSASetRawValueNoVendor(t *testing.T) {
	vsa := &VSA{
		StringValue: "testString",
		Name:        "testName",
		Vendor:      1,
	}

	dict := &Dictionary{
		RWMutex: sync.RWMutex{},
		vc: map[uint32]*DictionaryVendor{
			1: {
				VendorName:   "VendorName",
				VendorNumber: 2,
				Format:       "format",
			},
		},
	}
	cdr := Coder{}

	expvsa := &VSA{
		StringValue: "testString",
		Name:        "testName",
		Vendor:      1,
		VendorName:  dict.vc[vsa.Vendor].VendorName,
	}
	experr := fmt.Sprintf("missing dictionary data for VSA: %+v, ", expvsa)

	err := vsa.SetRawValue(dict, cdr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestAVPVSASetRawValueSuccess(t *testing.T) {
	vsa := &VSA{
		StringValue: "123",
		Number:      1,
		Vendor:      VendorSpecificNumber,
	}
	dict := &Dictionary{
		ac: map[uint32]map[uint8]*DictionaryAttribute{
			VendorSpecificNumber: {
				1: &DictionaryAttribute{
					AttributeName:   "dictName",
					AttributeNumber: 2,
					AttributeType:   IntegerValue,
				},
			},
		},
	}
	cdr := Coder{
		IntegerValue: codecs.IntegerCodec{},
	}

	// experr := ""
	err := vsa.SetRawValue(dict, cdr)

	if err != nil {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	exp := []byte{0, 0, 0, 123}

	if !reflect.DeepEqual(exp, vsa.RawValue) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, vsa.RawValue)
	}
}

func TestAVPVSASetRawValueUnsupportedAttribute1(t *testing.T) {
	vsa := &VSA{
		StringValue: "123",
		Value:       5,
		Type:        IntegerValue,
	}
	var dict *Dictionary
	var cdr Coder

	experr := "unsupported attribute type"
	err := vsa.SetRawValue(dict, cdr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestAVPVSASetRawValueUnsupportedAttribute2(t *testing.T) {
	vsa := &VSA{
		StringValue: "123",
		Type:        IntegerValue,
		VendorName:  "vendor",
		Name:        "name",
	}

	dict := &Dictionary{
		RWMutex: sync.RWMutex{},
		valName: map[string]map[string]map[string]*DictionaryValue{
			"vendor": {
				"name": {
					"123": &DictionaryValue{
						AttributeName: "attrName",
						ValueName:     "valName",
						ValueNumber:   2,
					},
				},
			},
		},
	}

	var cdr Coder

	experr := "unsupported attribute type"
	err := vsa.SetRawValue(dict, cdr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}
