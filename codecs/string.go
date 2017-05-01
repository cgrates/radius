package codecs

import (
	"errors"
)

// StringCodec is a codec for string values
type StringCodec struct{}

// Decode is part of AVPCoder interface
func (cdc StringCodec) Decode(b []byte) (v interface{}, s string, err error) {
	s = string(b)
	return s, s, nil
}

// Encode is part of AVPCoder interface
func (cdc StringCodec) Encode(v interface{}) (b []byte, err error) {
	strVal, ok := v.(string)
	if !ok {
		return nil, errors.New("cannot cast to string")
	}
	return []byte(strVal), nil
}

// EncodeString is part of AVPCoder interface
func (cdc StringCodec) EncodeString(s string) (b []byte, err error) {
	return cdc.Encode(s)
}
