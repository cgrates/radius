package radigo

import (
	"encoding/binary"
	"errors"
)

type AVP struct {
	Number   uint8       // attribute number
	rawValue []byte      // original value as byte
	Name     string      // attribute name
	Type     string      // type of the value helping us to convert to concrete
	Value    interface{} // holds the concrete value defined in dictionary, extracted back with type (eg: avp.Value.(string) or avp.Value.(*VSA))
}

func (a *AVP) Encode(b []byte) (n int, err error) {
	fullLen := len(a.rawValue) + 2 //type and length
	if fullLen > 255 || fullLen < 2 {
		return 0, errors.New("value too big for attribute")
	}
	b[0] = uint8(a.Number)
	b[1] = uint8(fullLen)
	copy(b[2:], a.rawValue)
	return fullLen, err
}

func NewVSAFromAVP(avp *AVP) (*VSA, error) {
	if avp.Number != VendorSpecific {
		return nil, errors.New("not VSA type")
	}
	vsa := new(VSA)
	vsa.Vendor = binary.BigEndian.Uint32(avp.rawValue[0:4])
	vsa.Number = uint8(avp.rawValue[4])
	vsa.rawValue = make([]byte, avp.rawValue[5]-2) // length field will include vendor type and vendor length, so deduct it here
	copy(vsa.rawValue, avp.rawValue[6:])
	return vsa, nil
}

// Vendor specific Attribute/Val
// originally ported from github.com/bronze1man/radius/avp_vendor.go
type VSA struct {
	Vendor   uint32
	Number   uint8       // attribute number
	rawValue []byte      // value as received over network
	Name     string      // attribute name
	Type     string      // type of the value helping us to convert to concrete
	Value    interface{} // holds the concrete value defined in dictionary, extracted back with type (eg: avp.Value.(string))
}

// encodes vsa back to AVP
func (vsa *VSA) AVP() *AVP {
	vsa_len := len(vsa.rawValue)
	// vendor id (4) + attr type (1) + attr len (1)
	vsa_value := make([]byte, vsa_len+6)
	binary.BigEndian.PutUint32(vsa_value[0:4], vsa.Vendor)
	vsa_value[4] = uint8(vsa.Number)
	vsa_value[5] = uint8(vsa_len + 2)
	copy(vsa_value[6:], vsa.rawValue)

	avp := &AVP{Number: VendorSpecific, rawValue: vsa_value}
	return avp
}
