package codecs

import (
	"encoding/binary"
	"fmt"
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
		return nil, fmt.Errorf("cannot cast <%v> to uint32", v)
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
	return cdc.Encode(uint32(i))
}
