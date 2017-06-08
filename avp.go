package radigo

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type AVP struct {
	Number      uint8       // attribute number
	Name        string      // attribute name
	Type        string      // type of the value helping us to convert to concrete
	RawValue    []byte      // original value as byte
	Value       interface{} // holds the concrete value defined in dictionary, extracted back with type (eg: avp.Value.(string) or avp.Value.(*VSA))
	StringValue string      // stores the string value for convenience and pretty print
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

// StringValue returns the string value from either AVP of VSA
func (a *AVP) GetStringValue() (strVal string) {
	if a.Number != VendorSpecificNumber {
		strVal = a.StringValue
	} else if vsa, cast := a.Value.(*VSA); cast { // for VSA, return string value of it
		strVal = vsa.StringValue
	}
	return
}

// SetValue populates Value with concrete data based on raw one
// abandons in case of Value already set
func (a *AVP) SetValue(dict *Dictionary, cdr Coder) (err error) {
	if a.Value != nil { // already set
		return
	}
	if a.Number == VendorSpecificNumber { // Special handling of VSA values
		vsa, err := NewVSAFromAVP(a)
		if err != nil {
			return err
		}
		if err := vsa.SetValue(dict, cdr); err != nil {
			return err
		}
		a.Name = VendorSpecificName
		a.Type = StringValue
		a.Value = vsa
		return nil
	}
	da := dict.AttributeWithNumber(a.Number, NoVendor)
	if da == nil {
		return fmt.Errorf("no dictionary data for avp: %+v", a)
	}
	val, strVal, err := cdr.Decode(da.AttributeType, a.RawValue)
	if err != nil {
		if err != ErrUnsupportedAttributeType {
			return err
		}
		a.Name = ErrUnsupportedAttributeType.Error()
		err = nil
	} else {
		a.Name = da.AttributeName
	}
	a.Type = da.AttributeType
	a.Value = val
	a.StringValue = strVal
	if a.Type == IntegerValue { // Attempty aliasing string value with the one from enum
		if dv := dict.ValueWithNumber(a.Name, uint8(a.Value.(uint32)), NoVendor); dv != nil {
			a.StringValue = dv.ValueName
		}
	}
	return
}

// SetRawValue will set the raw value (wire ready) from concrete one stored in interface
func (a *AVP) SetRawValue(dict *Dictionary, cdr Coder) (err error) {
	if a.RawValue != nil {
		return
	}
	if a.Value == nil && a.StringValue == "" {
		return fmt.Errorf("avp: %+v, no value", a)
	}
	if a.Type == "" {
		var da *DictionaryAttribute
		if a.Name != "" {
			da = dict.AttributeWithName(a.Name, "")
		} else if a.Number != 0 {
			da = dict.AttributeWithNumber(a.Number, 0)
		}
		if da == nil {
			return fmt.Errorf("%+v, missing dictionary data", a)
		}
		a.Name = da.AttributeName
		a.Type = da.AttributeType
		a.Number = da.AttributeNumber
	}
	if a.Number == VendorSpecificNumber { // handle VSA differently
		vsa, ok := a.Value.(*VSA)
		if !ok {
			return fmt.Errorf("%+v, cannot cast to VSA", a)
		}
		if err := vsa.SetRawValue(dict, cdr); err != nil {
			return err
		}
		a.RawValue = vsa.AVP().RawValue
		return
	}
	var rawVal []byte
	if a.Value != nil {
		if rawVal, err = cdr.Encode(a.Type, a.Value); err != nil {
			return err
		}
	} else { // Consider stirng for encoding
		if rawVal, err = cdr.EncodeString(a.Type, a.StringValue); err != nil {
			return err
		}
	}
	a.RawValue = rawVal
	return nil
}

func NewVSAFromAVP(avp *AVP) (*VSA, error) {
	if avp.Number != VendorSpecificNumber {
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
	Vendor      uint32
	Number      uint8       // attribute number
	VendorName  string      // populated by dictionary
	Name        string      // attribute name
	Type        string      // type of the value helping us to convert to concrete
	Value       interface{} // holds the concrete value defined in dictionary, extracted back with type (eg: avp.Value.(string))
	RawValue    []byte      // value as received over network
	StringValue string      // stores the string value
}

// AVP encodes VSA back into AVP
func (vsa *VSA) AVP() *AVP {
	vsa_len := len(vsa.RawValue)
	// vendor id (4) + attr type (1) + attr len (1)
	vsa_value := make([]byte, vsa_len+6)
	binary.BigEndian.PutUint32(vsa_value[0:4], vsa.Vendor)
	vsa_value[4] = uint8(vsa.Number)
	vsa_value[5] = uint8(vsa_len + 2)
	copy(vsa_value[6:], vsa.RawValue)
	return &AVP{Number: VendorSpecificNumber, RawValue: vsa_value}
}

// SetValue populates Value elements based on vsa.RawValue
func (vsa *VSA) SetValue(dict *Dictionary, cdr Coder) (err error) {
	if vsa.Value != nil { // already set, maybe in application
		return
	}
	da := dict.AttributeWithNumber(vsa.Number, vsa.Vendor)
	if da == nil {
		return ErrDictionaryNotFound
	}
	val, strVal, err := cdr.Decode(da.AttributeType, vsa.RawValue)
	if err != nil {
		if err != ErrUnsupportedAttributeType {
			return err
		}
		vsa.Name = ErrUnsupportedAttributeType.Error()
		err = nil
	} else {
		vsa.Name = da.AttributeName
	}
	vsa.Type = da.AttributeType
	vsa.Value = val
	vsa.StringValue = strVal
	if vsa.Type == IntegerValue { // Attempty aliasing string value with the one from enum
		if dv := dict.ValueWithNumber(vsa.Name, vsa.Value.(uint8), vsa.Vendor); dv != nil {
			vsa.StringValue = dv.ValueName
		}
	}
	return
}

// SetRawValue populates RawValue(wire data) based on concrete stored in vsa.Value
func (vsa *VSA) SetRawValue(dict *Dictionary, cdr Coder) (err error) {
	if vsa.RawValue != nil { // already set
		return
	}
	if vsa.Value == nil && vsa.StringValue == "" {
		return fmt.Errorf("no value in VSA: %+v", vsa)
	}
	if vsa.Type == "" {
		var da *DictionaryAttribute
		if vsa.Number != 0 && vsa.Vendor != NoVendor {
			da = dict.AttributeWithNumber(vsa.Number, vsa.Vendor)
		} else if vsa.Name != "" {
			if vsa.VendorName == "" {
				if vndr := dict.VendorWithCode(vsa.Vendor); vndr == nil {
					return fmt.Errorf("no vendor in dictionary for VSA: %+v, ", vsa)
				} else {
					vsa.VendorName = vndr.VendorName
				}
			}
			da = dict.AttributeWithName(vsa.Name, vsa.VendorName)
		}
		if da == nil {
			return fmt.Errorf("missing dictionary data for VSA: %+v, ", vsa)
		}
		vsa.Name = da.AttributeName
		vsa.Type = da.AttributeType
		vsa.Number = da.AttributeNumber
	}
	var rawVal []byte
	if vsa.Value != nil {
		if rawVal, err = cdr.Encode(vsa.Type, vsa.Value); err != nil {
			return err
		}
	} else {
		if rawVal, err = cdr.EncodeString(vsa.Type, vsa.StringValue); err != nil {
			return err
		}
	}
	vsa.RawValue = rawVal
	return
}
