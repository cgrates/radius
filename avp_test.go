package radigo

import (
	"reflect"
	"testing"
)

func TestVSAToAVP(t *testing.T) {
	vsa := &VSA{
		Vendor:   9,
		Number:   23,
		rawValue: []byte("CGRateS.org"),
	}
	eAVP := &AVP{
		Number: VendorSpecific,
		rawValue: []byte{0x00, 0x00, 0x00, 0x09,
			0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67},
	}
	if avp := vsa.AVP(); !reflect.DeepEqual(eAVP, avp) {
		t.Errorf("Expecting: %+v, received: %+v", eAVP, avp)
	}
}

func TestNewVSAFromAVP(t *testing.T) {
	avp := &AVP{
		Number: VendorSpecific,
		rawValue: []byte{0x00, 0x00, 0x00, 0x09,
			0x17, 0x0d, 0x43, 0x47, 0x52, 0x61, 0x74, 0x65, 0x53, 0x2e, 0x6f, 0x72, 0x67},
	}
	eVsa := &VSA{
		Vendor:   9,
		Number:   23,
		rawValue: []byte("CGRateS.org"),
	}
	if vsa, err := NewVSAFromAVP(avp); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(eVsa, vsa) {
		t.Errorf("Expecting: %+v, received: %+v", eVsa, vsa)
	}
}
