package codecs

// OctetsCodec is a codec for string values
type OctetsCodec struct{}

// Decode is part of AVPCoder interface
func (cdc OctetsCodec) Decode(b []byte) (v interface{}, s string, err error) {
	return b, string(b), nil
}

// Encode is part of AVPCoder interface
func (cdc OctetsCodec) Encode(v interface{}) (b []byte, err error) {
	return v.([]byte), nil
}

// EncodeString is part of AVPCoder interface
func (cdc OctetsCodec) EncodeString(s string) (b []byte, err error) {
	return []byte(s), nil
}
