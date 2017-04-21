package radigo

import (
	"net"
	"reflect"
	"testing"
)

func TestVSAToAVP(t *testing.T) {
	vsa := &VSA{
		Vendor:   9,
		Number:   23,
		RawValue: []byte("CGRateS.org"),
	}
	eAVP := &AVP{
		Number: VendorSpecific,
		RawValue: []byte{0x00, 0x00, 0x00, 0x09,
			0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67},
	}
	if avp := vsa.AVP(); !reflect.DeepEqual(eAVP, avp) {
		t.Errorf("Expecting: %+v, received: %+v", eAVP, avp)
	}
}

func TestNewVSAFromAVP(t *testing.T) {
	avp := &AVP{
		Number: VendorSpecific,
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
		Type:     addressVal,
		Value:    net.IP(avp.RawValue),
	}
	if err := avp.SetValue(RFC2865Dictionary()); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(eAvp.Value, avp.Value) {
		t.Errorf("Expecting: %+v, received: %+v", eAvp, avp)
	}
}

func TestIfaceToBytes(t *testing.T) {
	ip := net.ParseIP("192.168.1.16")
	eBts := []byte{0xc0, 0xa8, 0x01, 0x10}
	if bts, err := ifaceToBytes(addressVal, ip); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(eBts, bts) {
		t.Errorf("Expecting: %+v, received: %+v", eBts, bts)
	}
	cgr := "CGRateS.org"
	eBts = []byte{0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67}
	if bts, err := ifaceToBytes(stringVal, cgr); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(eBts, bts) {
		t.Errorf("Expecting: %+v, received: %+v", eBts, bts)
	}
}
