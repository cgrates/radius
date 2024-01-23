package codecs

import (
	"errors"
	"net"
)

// AddressCodec is a codec for address values
type AddressCodec struct{}

// Decode is part of AVPCoder interface
func (cdc AddressCodec) Decode(b []byte) (v interface{}, s string, err error) {
	ip := net.IP(b)
	return ip, ip.String(), nil

}

// Encode is part of AVPCoder interface
func (cdc AddressCodec) Encode(v interface{}) ([]byte, error) {
	ipVal, ok := v.(net.IP)
	if !ok {
		return nil, errors.New("cannot cast to net.IP")
	}
	ipVal = ipVal.To4()
	if ipVal == nil {
		return nil, errors.New("cannot enforce IPv4")
	}
	return []byte(ipVal), nil
}

// EncodeString is part of AVPCoder interface
func (cdc AddressCodec) EncodeString(s string) (b []byte, err error) {
	return cdc.Encode(net.ParseIP(s))
}
