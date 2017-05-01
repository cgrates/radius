package codecs

import (
	"encoding/binary"
	"errors"
	"strconv"
)

// IntegerCodec is a codec for string values
type IntegerCodec struct{}

// Decode is part of AVPCoder interface
func (cdc IntegerCodec) Decode(b []byte) (v interface{}, s string, err error) {
	i := binary.BigEndian.Uint32(b)
	return i, strconv.Itoa(int(i)), nil
}

// Encode is part of AVPCoder interface
func (cdc IntegerCodec) Encode(v interface{}) (b []byte, err error) {
	intVal, ok := v.(uint32)
	if !ok {
		return nil, errors.New("cannot cast to uint32")
	}
	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, intVal)
	return
}

// EncodeString is part of AVPCoder interface
func (cdc IntegerCodec) EncodeString(s string) (b []byte, err error) {
	var i int
	if i, err = strconv.Atoi(s); err != nil {
		return
	}
	return cdc.Encode(i)
}
