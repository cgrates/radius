package radigo

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

const (
	AccessRequest      PacketCode = 1
	AccessAccept       PacketCode = 2
	AccessReject       PacketCode = 3
	AccountingRequest  PacketCode = 4
	AccountingResponse PacketCode = 5
	AccessChallenge    PacketCode = 11
	StatusServer       PacketCode = 12 //(experimental)
	StatusClient       PacketCode = 13 //(experimental)
	Reserved           PacketCode = 255
	ReplyMessage                  = 18
	VendorSpecific                = 26 // vendor specific AVP number
	NoVendor                      = 0
)

// computeAuthenticator computes the authenticator
// raw is the data received or to be sent over network
func computeAuthenticator(raw []byte, secret string) (acator [16]byte) {
	pCode := PacketCode(raw[0])
	switch pCode {
	case AccessRequest: // we generate the packet
		rand.Read(acator[:]) // generate a random authenticator
	case AccessAccept, AccessReject, AccessChallenge, AccountingRequest, AccountingResponse:
		if pCode == AccountingRequest { // AccountingRequest concatenates null instead of previous authenticator so we trick it here
			var nul [16]byte
			copy(raw[4:20], nul[:])
		}
		hash := md5.New()
		hash.Write(raw[:])
		hash.Write([]byte(secret))
		copy(acator[:], hash.Sum(nil))
	}
	return
}

type PacketCode uint8

func (p PacketCode) String() string {
	switch p {
	case AccessRequest:
		return "AccessRequest"
	case AccessAccept:
		return "AccessAccept"
	case AccessReject:
		return "AccessReject"
	case AccountingRequest:
		return "AccountingRequest"
	case AccountingResponse:
		return "AccountingResponse"
	case AccessChallenge:
		return "AccessChallenge"
	case StatusServer:
		return "StatusServer"
	case StatusClient:
		return "StatusClient"
	case Reserved:
		return "Reserved"
	}
	return "unknown packet code"
}

func (p *Packet) Has(attrNr uint8) bool {
	for i, _ := range p.AVPs {
		if p.AVPs[i].Number == attrNr {
			return true
		}
	}
	return false
}

type Packet struct {
	dict          *Dictionary
	secret        string
	Code          PacketCode
	Identifier    uint8
	Authenticator [16]byte
	AVPs          []*AVP
}

// Encode is used to encode the Packet into buffer b returning number of bytes written or error
func (p *Packet) Encode(b []byte) (n int, err error) {
	b[0] = uint8(p.Code)
	b[1] = uint8(p.Identifier)
	copy(b[4:20], p.Authenticator[:])
	written := 20
	bb := b[20:]
	for _, avp := range p.AVPs {
		if avp.RawValue == nil { // Need to encode concrete into raw
			if avp.RawValue, err = ifaceToBytes(avp.Type, avp.Value); err != nil {
				return
			}
		}
		n, err = avp.Encode(bb)
		written += n
		if err != nil {
			return written, err
		}
		bb = bb[n:]
	}
	binary.BigEndian.PutUint16(b[2:4], uint16(written))
	p.Authenticator = computeAuthenticator(b[:], p.secret)
	copy(b[4:20], p.Authenticator[:])
	return written, err
}

func (p *Packet) Decode(buf []byte) error {
	p.Code = PacketCode(buf[0])
	p.Identifier = buf[1]
	copy(p.Authenticator[:], buf[4:20])
	//read attributes
	b := buf[20:]
	for len(b) >= 2 {
		avp := new(AVP)
		avp.Number = b[0]
		length := uint8(b[1])
		if int(length) > len(b) {
			return errors.New("invalid length")
		}
		avp.RawValue = append(avp.RawValue, b[2:length]...)
		p.AVPs = append(p.AVPs, avp)
		b = b[length:]
	}
	return nil
}

func (p *Packet) Attributes(attrNr uint8) []*AVP {
	ret := []*AVP(nil)
	for i, _ := range p.AVPs {
		if p.AVPs[i].Number == attrNr {
			ret = append(ret, p.AVPs[i])
		}
	}
	return ret

}

func (p *Packet) Reply() *Packet {
	return &Packet{
		dict:          p.dict,
		secret:        p.secret,
		Identifier:    p.Identifier,
		Authenticator: p.Authenticator,
	}
}

// NegativeReply generates a reply with unsuccess for received packet
func (p *Packet) NegativeReply(errMsg string) (rply *Packet) {
	rply = p.Reply()
	switch p.Code {
	case AccessRequest:
		rply.Code = AccessReject
		rply.AVPs = append(rply.AVPs, &AVP{Number: ReplyMessage, RawValue: []byte(errMsg)})
	case AccountingRequest:
		rply.Code = AccountingResponse
		rply.AVPs = append(rply.AVPs, &AVP{Number: ReplyMessage, RawValue: []byte(errMsg)})
	}
	return
}
