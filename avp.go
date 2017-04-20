package radigo

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
	"unicode/utf8"
)

var errUnsupportedAttributeType = errors.New("unsupported attribute type")

type AVP struct {
	sync.RWMutex
	Number   uint8       // attribute number
	RawValue []byte      // original value as byte
	Name     string      // attribute name
	Type     string      // type of the value helping us to convert to concrete
	Value    interface{} // holds the concrete value defined in dictionary, extracted back with type (eg: avp.Value.(string) or avp.Value.(*VSA))
}

func (a *AVP) Encode(b []byte) (n int, err error) {
	fullLen := len(a.RawValue) + 2 //type and length
	if fullLen > 255 || fullLen < 2 {
		return 0, errors.New("value too big for attribute")
	}
	b[0] = uint8(a.Number)
	b[1] = uint8(fullLen)
	copy(b[2:], a.RawValue)
	return fullLen, err
}

// SetValue populates Value with the right interface value
// abandons in case of Value already set
func (a *AVP) SetValue(da *DictionaryAttribute) (err error) {
	if a.Name != "" { // already set
		return
	}
	a.Lock()
	defer a.Unlock()
	if a.Number == VendorSpecific { // Special handling of VSA values
		vsa, err := NewVSAFromAVP(a)
		if err != nil {
			return err
		}
		if err := vsa.SetValue(da); err != nil {
			return err
		}
		a.Name = "Vendor-Specific"
		a.Type = stringVal
		a.Value = vsa
		return nil
	}
	val, err := decodeAVPValue(da.AttributeType, a.RawValue)
	if err != nil {
		if err != errUnsupportedAttributeType {
			return err
		}
		a.Name = errUnsupportedAttributeType.Error()
	} else {
		a.Name = da.AttributeName
	}
	a.Type = da.AttributeType
	a.Value = val
	return
}

func NewVSAFromAVP(avp *AVP) (*VSA, error) {
	if avp.Number != VendorSpecific {
		return nil, errors.New("not VSA type")
	}
	vsa := new(VSA)
	vsa.Vendor = binary.BigEndian.Uint32(avp.RawValue[0:4])
	vsa.Number = uint8(avp.RawValue[4])
	vsa.RawValue = make([]byte, avp.RawValue[5]-2) // length field will include vendor type and vendor length, so deduct it here
	copy(vsa.RawValue, avp.RawValue[6:])
	return vsa, nil
}

// Vendor specific Attribute/Val
// originally ported from github.com/bronze1man/radius/avp_vendor.go
type VSA struct {
	sync.RWMutex
	Vendor     uint32
	Number     uint8       // attribute number
	RawValue   []byte      // value as received over network
	VendorName string      // populated by dictionary
	Name       string      // attribute name
	Type       string      // type of the value helping us to convert to concrete
	Value      interface{} // holds the concrete value defined in dictionary, extracted back with type (eg: avp.Value.(string))
}

// encodes vsa back into AVP
func (vsa *VSA) AVP() *AVP {
	vsa_len := len(vsa.RawValue)
	// vendor id (4) + attr type (1) + attr len (1)
	vsa_value := make([]byte, vsa_len+6)
	binary.BigEndian.PutUint32(vsa_value[0:4], vsa.Vendor)
	vsa_value[4] = uint8(vsa.Number)
	vsa_value[5] = uint8(vsa_len + 2)
	copy(vsa_value[6:], vsa.RawValue)
	avp := &AVP{Number: VendorSpecific, RawValue: vsa_value}
	return avp
}

func (vsa *VSA) SetValue(da *DictionaryAttribute) (err error) {
	if vsa.Name != "" { // already set, maybe in application
		return
	}
	vsa.Lock()
	defer vsa.Unlock()
	val, err := decodeAVPValue(da.AttributeType, vsa.RawValue)
	if err != nil {
		if err != errUnsupportedAttributeType {
			return err
		}
		vsa.Name = errUnsupportedAttributeType.Error()
	} else {
		vsa.Name = da.AttributeName
	}
	vsa.Type = da.AttributeType
	vsa.Value = val
	return
}

// decodeAVPValue converts raw bytes received over the network into concrete Go datatype
func decodeAVPValue(valType string, rawValue []byte) (interface{}, error) {
	switch valType {
	case textVal:
		if !utf8.Valid(rawValue) {
			return nil, errors.New("not valid UTF-8")
		}
		return string(rawValue), nil
	case stringVal:
		return string(rawValue), nil
	case integerVal:
		return binary.BigEndian.Uint32(rawValue), nil
	case ipaddrVal, addressVal:
		//v := make([]byte, len(rawValue))
		//copy(v, rawValue)
		return net.IP(rawValue), nil
	case timeVal:
		return time.Unix(int64(binary.BigEndian.Uint32(rawValue)), 0), nil
	default: // unknown value, will be decoded upstream most probably
		return rawValue, errUnsupportedAttributeType
	}
}

// ifaceToBytes converts the concrete Go value in AVP into []byte stream ready to be sent over network
func ifaceToBytes(valType string, val interface{}) ([]byte, error) {
	switch valType {
	case textVal, stringVal:
		strVal, ok := val.(string)
		if !ok {
			return nil, errors.New("cannot cast to string")
		}
		return []byte(strVal), nil
	case integerVal:
		intVal, ok := val.(uint32)
		if !ok {
			return nil, errors.New("cannot cast to uint32")
		}
		rawVal := make([]byte, 4)
		binary.BigEndian.PutUint32(rawVal, intVal)
		return rawVal, nil
	case ipaddrVal, addressVal:
		ipVal, ok := val.(net.IP)
		if !ok {
			return nil, errors.New("cannot cast to net.IP")
		}
		ipVal = ipVal.To4()
		if ipVal == nil {
			return nil, errors.New("cannot enforce IPv4")
		}
		return []byte(ipVal), nil
	case timeVal:
		tmstmpVal, ok := val.(time.Time)
		if !ok {
			return nil, errors.New("cannot cast to time.Time")
		}
		rawVal := make([]byte, 4)
		binary.BigEndian.PutUint32(rawVal, uint32(tmstmpVal.Unix()))
		return rawVal, nil
	default:
		rawVal, ok := val.([]byte)
		if !ok {
			return nil, errors.New("cannot cast unknown value to []byte")
		}
		return rawVal, nil
	}
}
