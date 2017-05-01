package codecs

import (
	"errors"
	"unicode/utf8"
)

// TextCodec is a codec for string values
type TextCodec struct{}

// Decode is part of AVPCoder interface
func (cdc TextCodec) Decode(b []byte) (v interface{}, s string, err error) {
	if !utf8.Valid(b) {
		err = errors.New("not valid UTF-8")
		return
	}
	strVal := string(s)
	return strVal, strVal, nil
}

// Encode is part of AVPCoder interface
func (cdc TextCodec) Encode(v interface{}) (b []byte, err error) {
	strVal, ok := v.(string)
	if !ok {
		return nil, errors.New("cannot cast to string")
	}
	return []byte(strVal), nil
}

// EncodeString is part of AVPCoder interface
func (cdc TextCodec) EncodeString(s string) (b []byte, err error) {
	return cdc.Encode(s)
}
