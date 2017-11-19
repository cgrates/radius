package codecs

import (
	"encoding/binary"
	"errors"
	"time"
)

// TimeCodec is a codec for time values
type TimeCodec struct{}

// Decode is part of AVPCoder interface
func (cdc TimeCodec) Decode(b []byte) (v interface{}, s string, err error) {
	t := time.Unix(int64(binary.BigEndian.Uint32(b)), 0)
	return t, t.Format(time.RFC3339), nil
}

// Encode is part of AVPCoder interface
func (cdc TimeCodec) Encode(v interface{}) (b []byte, err error) {
	tmstmpVal, ok := v.(time.Time)
	if !ok {
		return nil, errors.New("cannot cast to time.Time")
	}
	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(tmstmpVal.Unix()))
	return
}

// EncodeString is part of AVPCoder interface
func (cdc TimeCodec) EncodeString(s string) (b []byte, err error) {
	var t time.Time
	if t, err = time.Parse(time.RFC3339, s); err != nil {
		return
	}
	return cdc.Encode(t)
}
