package radigo

type AVPCodec interface {
	Decode(*Packet, *AVP) error // populates AVP ifaceValue and strValue out of rawValue
	Encode(*Packet, *AVP) error // populates AVP rawValue out of ifaceValue
}

// StringCodec is a codec for string values
type StringCodec struct{}

// Decode is part of AVPCodec interface
func (cdc StringCodec) Decode(p *Packet, a *AVP) (err error) {
	return
}

// Encode is part of AVPCodec interface
func (cdc StringCodec) Encode(p *Packet, a *AVP) (err error) {
	return
}
