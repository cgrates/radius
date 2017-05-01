package radigo

import (
	"github.com/cgrates/radigo/codecs"
)

func NewCoder() Coder {
	return Coder{
		StringValue:  codecs.StringCodec{},
		TextValue:    codecs.TextCodec{},
		AddressValue: codecs.AddressCodec{},
		IPAddrValue:  codecs.AddressCodec{},
		IntegerValue: codecs.IntegerCodec{},
		TimeValue:    codecs.TimeCodec{},
	}
}

// Coder puts together the available codecs
// Key represents the attribute type as defined in dictionary
type Coder map[string]codecs.AVPCoder

// Decode converts raw value received over network into concrete value stored in AVP and it's string representation
func (cdr Coder) Decode(attrType string, b []byte) (v interface{}, s string, err error) {
	if _, has := cdr[attrType]; !has {
		err = ErrUnsupportedAttributeType
		return
	}
	return cdr[attrType].Decode(b)
}

// Encode converts concrete value into raw value to be sent over the network
func (cdr Coder) Encode(attrType string, v interface{}) (b []byte, err error) {
	if _, has := cdr[attrType]; !has {
		err = ErrUnsupportedAttributeType
		return
	}
	return cdr[attrType].Encode(v)
}
