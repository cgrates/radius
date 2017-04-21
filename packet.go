package radigo

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
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

// IsAuthentic should be called by client to make sure the reply is authentic
// reqAuthenticator is the original request authenticator to be matched against
func isAuthentic(rawPkt []byte, secret string, reqAuthenticator [16]byte) bool {
	var pktAcator [16]byte
	copy(pktAcator[:], rawPkt[4:20])
	copy(rawPkt[4:20], reqAuthenticator[:])
	shouldBeAcator := computeAuthenticator(rawPkt, secret)
	return bytes.Equal(pktAcator[:], shouldBeAcator[:])
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
// ToDo: Optimize the code duplication due to VSA searches
func (p *Packet) Encode(b []byte) (n int, err error) {
	b[0] = uint8(p.Code)
	b[1] = uint8(p.Identifier)
	copy(b[4:20], p.Authenticator[:])
	written := 20
	bb := b[20:]
	for _, avp := range p.AVPs {
		if avp.RawValue == nil { // Need to encode concrete into raw
			if avp.Value == nil {
				return 0, fmt.Errorf("failed encoding avp: %+v, no value", avp)
			}
			if avp.Type == "" {
				var da *DictionaryAttribute
				if avp.Name != "" {
					da = p.dict.AttributeWithName(avp.Name, "")
				} else if avp.Number != 0 {
					da = p.dict.AttributeWithNumber(avp.Number, 0)
				}
				if da == nil {
					return 0, fmt.Errorf("failed encoding avp: %+v, missing dictionary data", avp)
				}
				avp.Name = da.AttributeName
				avp.Type = da.AttributeType
				avp.Number = da.AttributeNumber
			}
			if avp.Number == VendorSpecific { // handle VSA differently
				vsa, ok := avp.Value.(*VSA)
				if !ok {
					return 0, fmt.Errorf("failed encoding avp: %+v, cannot extract VSA", avp)
				}
				if vsa.RawValue == nil {
					if vsa.Value == nil {
						return 0, fmt.Errorf("failed encoding vsa: %+v, no value", vsa)
					}
					if vsa.Type == "" {
						var da *DictionaryAttribute
						if vsa.Name != "" {
							if vsa.VendorName == "" {
								if vndr := p.dict.VendorWithCode(vsa.Vendor); vndr == nil {
									return 0, fmt.Errorf("failed encoding vsa: %+v, no vendor in dictionary", vsa)
								} else {
									vsa.VendorName = vndr.VendorName
								}
							}
							da = p.dict.AttributeWithName(vsa.Name, vsa.VendorName)
						} else if avp.Number != 0 {
							da = p.dict.AttributeWithNumber(avp.Number, vsa.Vendor)
						}
						if da == nil {
							return 0, fmt.Errorf("failed encoding vsa: %+v, missing dictionary data", vsa)
						}
						vsa.Name = da.AttributeName
						vsa.Type = da.AttributeType
						vsa.Number = da.AttributeNumber
					}
					if vsa.RawValue, err = ifaceToBytes(vsa.Type, vsa.Value); err != nil {
						return
					}
				}
				avp.RawValue = vsa.AVP().RawValue
			} else if avp.RawValue, err = ifaceToBytes(avp.Type, avp.Value); err != nil {
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
	p.Authenticator = computeAuthenticator(b[:written], p.secret)
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
