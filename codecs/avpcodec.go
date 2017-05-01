package codecs

// AVPCodec is the interface implementing a codec for radigo.AVP
type AVPCoder interface {
	Decode([]byte) (interface{}, string, error)
	Encode(interface{}) ([]byte, error)
}
