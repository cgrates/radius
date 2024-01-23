package radigo

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
)

const (
	AccessRequest        PacketCode = 1
	AccessAccept         PacketCode = 2
	AccessReject         PacketCode = 3
	AccountingRequest    PacketCode = 4
	AccountingResponse   PacketCode = 5
	AccessChallenge      PacketCode = 11
	StatusServer         PacketCode = 12 //(experimental)
	StatusClient         PacketCode = 13 //(experimental)
	DisconnectRequest    PacketCode = 40
	DisconnectACK        PacketCode = 41
	DisconnectNAK        PacketCode = 42
	CoARequest           PacketCode = 43
	CoAACK               PacketCode = 44
	CoANAK               PacketCode = 45
	Reserved             PacketCode = 255
	ReplyMessage                    = 18
	VendorSpecificNumber            = 26 // vendor specific AVP number
	VendorSpecificName              = "Vendor-Specific"
	NoVendor                        = 0
)

var (
	ErrNotImplemented = errors.New("not implemented")
)

// computeAuthenticator computes the authenticator based on packet code, raw data, and secret.
func computeAuthenticator(raw []byte, secret string) (acator [16]byte) {
	pCode := PacketCode(raw[0])
	switch pCode {
	case AccessRequest:
		// For AccessRequest, use the authenticator provided in the request.
		copy(acator[:], raw[4:20])

	case AccessAccept, AccessReject, AccessChallenge, AccountingRequest, AccountingResponse, DisconnectRequest, DisconnectACK, DisconnectNAK, CoARequest, CoAACK, CoANAK:
		// Special handling for certain packet codes that require null authenticator.
		switch pCode {
		case AccountingRequest, DisconnectRequest, CoARequest:
			var nul [16]byte
			copy(raw[4:20], nul[:])
		}

		// Compute MD5 hash using the packet's raw data and the secret.
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
	case DisconnectRequest:
		return "DisconnectRequest"
	case DisconnectACK:
		return "DisconnectACK"
	case DisconnectNAK:
		return "DisconnectNAK"
	case CoARequest:
		return "CoARequest"
	case CoAACK:
		return "CoAACK"
	case CoANAK:
		return "CoANAK"
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

// NewPacket creates a fresh packet, used mostly for testing
func NewPacket(code PacketCode, id uint8, dict *Dictionary, coder Coder, secret string) *Packet {
	return &Packet{
		Code:       code,
		Identifier: id,
		dict:       dict,
		coder:      coder,
		secret:     secret,
	}
}

type Packet struct {
	sync.RWMutex
	dict          *Dictionary
	coder         Coder // handles coding/encoding of AVP values
	secret        string
	Code          PacketCode
	Identifier    uint8
	Authenticator [16]byte
	AVPs          []*AVP
	addr          net.Addr
}

// Encode is used to encode the Packet into buffer b returning number of bytes written or error
func (p *Packet) Encode(b []byte) (n int, err error) {
	p.RLock()
	defer p.RUnlock()
	b[0] = uint8(p.Code)
	b[1] = uint8(p.Identifier)
	copy(b[4:20], p.Authenticator[:])
	written := 20
	bb := b[20:]
	for _, avp := range p.AVPs {
		if avp.RawValue == nil { // Need to encode concrete into raw
			if err := avp.SetRawValue(p.dict, p.coder); err != nil {
				return 0, err
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
	p.RLock()
	defer p.RUnlock()
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
		if validation, has := validation[avp.Number]; has {
			if err := validation.Validate(p, avp); err != nil {
				return err
			}
		}
		p.AVPs = append(p.AVPs, avp)
		b = b[length:]
	}
	return nil
}

func (p *Packet) Reply() *Packet {
	return &Packet{
		dict:          p.dict,
		secret:        p.secret,
		coder:         p.coder,
		Identifier:    p.Identifier,
		Authenticator: p.Authenticator,
	}
}

// NegativeReply generates a response packet indicating a failure or rejection based on the original request.
func (p *Packet) NegativeReply(errMsg string) *Packet {
	rply := p.Reply() // Create a reply packet based on the original request.

	// Set the response code based on the type of the request.
	switch p.Code {
	case AccessRequest:
		rply.Code = AccessReject
	case AccountingRequest:
		// Normally, RFC 2866 (Section 4.1.) advises against sending negative replies for AccountingRequest,
		// but this allows the possibility to remain RFC agnostic.
		rply.Code = AccountingResponse

	case CoARequest:
		rply.Code = CoANAK
	case DisconnectRequest:
		rply.Code = DisconnectNAK
	default:
		// If the request type is not handled, return the original reply.
		return rply
	}

	// Add the error message to the Reply-Message attribute.
	rply.AVPs = append(rply.AVPs, &AVP{Number: ReplyMessage, RawValue: []byte(errMsg)})

	return rply
}

func (p *Packet) SetAVPValues() {
	for _, avp := range p.AVPs {
		if err := avp.SetValue(p.dict, p.coder); err != nil {
			log.Printf("failed setting value for avp: %+v, err: %s\n", avp, err.Error())
		}
		if validation, has := validation[avp.Number]; has {
			if err := validation.Validate(p, avp); err != nil {
				log.Printf("failed validating value for avp: %+v, err: %s\n", avp, err.Error())
			}
		}
	}
}

// SetCodeWithName sets the packet code based on predefined name
func (p *Packet) SetCodeWithName(codeName string) (err error) {
	switch codeName {
	case "AccessRequest":
		p.Code = AccessRequest
	case "AccessAccept":
		p.Code = AccessAccept
	case "AccessReject":
		p.Code = AccessReject
	case "AccountingRequest":
		p.Code = AccountingRequest
	case "AccountingResponse":
		p.Code = AccountingResponse
	case "AccessChallenge":
		p.Code = AccessChallenge
	case "StatusServer":
		p.Code = StatusServer
	case "StatusClient":
		p.Code = StatusClient
	case "DisconnectRequest":
		p.Code = DisconnectRequest
	case "DisconnectACK":
		p.Code = DisconnectACK
	case "DisconnectNAK":
		p.Code = DisconnectNAK
	case "CoARequest":
		p.Code = CoARequest
	case "CoAACK":
		p.Code = CoAACK
	case "CoANAK":
		p.Code = CoANAK
	case "Reserved":
		p.Code = Reserved
	default:
		return fmt.Errorf("unsupported packet code name: <%s>", codeName)
	}
	return
}

// AttributesWithNumber queries AVPs matching the attrNr
// if vendorCode is defined, AttributesWithNumber will query VSAs
func (p *Packet) AttributesWithNumber(attrNr uint8, vendorCode uint32) (avps []*AVP) {
	p.RLock()
	defer p.RUnlock()
	qryNr := attrNr
	if vendorCode != NoVendor { // if vendor is not 0 we will emulate query on VendorSpecific number and consider sub
		qryNr = VendorSpecificNumber
	}
	for _, avp := range p.AVPs {
		if avp.Number == qryNr {
			if err := avp.SetValue(p.dict, p.coder); err != nil {
				log.Printf("failed setting value for avp: %+v, err: %s\n", avp, err.Error())
				continue
			}
			if vendorCode != NoVendor {
				if vsa, ok := avp.Value.(*VSA); !ok {
					log.Printf("failed converting VSA value for AVP: %+v\n", avp)
					continue
				} else if vsa.Number != attrNr {
					continue
				}
			}
			avps = append(avps, avp)
		}
	}
	return
}

// Attributes queries AVPs matching the attrNr
func (p *Packet) AttributesWithName(attrName, vendorName string) (avps []*AVP) {
	da := p.dict.AttributeWithName(attrName, vendorName)
	if da == nil {
		return
	}
	var vc uint32
	if vendorName != "" {
		if dv := p.dict.VendorWithName(vendorName); dv == nil {
			return
		} else {
			vc = dv.VendorNumber
		}
	}
	return p.AttributesWithNumber(da.AttributeNumber, vc)
}

// AddAVPWithNumber adds an AVP based on it's attribute number and value
func (p *Packet) AddAVPWithNumber(attrNr uint8, val interface{}, vendorCode uint32) (err error) {
	d := p.dict.AttributeWithNumber(attrNr, vendorCode)
	if d == nil {
		return fmt.Errorf("DICTIONARY_NOT_FOUND, item %d, vendor: %d", attrNr, vendorCode)
	}
	var avp *AVP
	if vendorCode == NoVendor {
		avp = &AVP{
			Number: attrNr,
			Name:   d.AttributeName,
			Type:   d.AttributeType,
			Value:  val,
		}
	} else {
		avp = &AVP{
			Number: VendorSpecificNumber,
			Name:   VendorSpecificName,
			Type:   StringValue,
			Value: &VSA{
				Vendor: vendorCode,
				Number: attrNr,
				Name:   d.AttributeName,
				Type:   d.AttributeType,
				Value:  val,
			},
		}
	}
	if err = avp.SetRawValue(p.dict, p.coder); err != nil {
		return
	}
	p.AVPs = append(p.AVPs, avp)
	return
}

// AddAVPWithName adds an AVP based on it's attribute name and string value
func (p *Packet) AddAVPWithName(attrName, strVal, vendorName string) (err error) {
	d := p.dict.AttributeWithName(attrName, vendorName)
	if d == nil {
		errStr := fmt.Sprintf("DICTIONARY_NOT_FOUND, attributeName: <%s>", attrName)
		if vendorName != "" {
			errStr = fmt.Sprintf("DICTIONARY_NOT_FOUND, attributeName: <%s>, vendorName: <%s>", attrName, vendorName)
		}
		return errors.New(errStr)
	}
	var avp *AVP
	if vendorName == "" {
		avp = &AVP{
			Number:      d.AttributeNumber,
			Name:        attrName,
			Type:        d.AttributeType,
			StringValue: strVal,
		}
	} else {
		avp = &AVP{
			Number: VendorSpecificNumber,
			Name:   VendorSpecificName,
			Type:   StringValue,
			Value: &VSA{
				VendorName:  vendorName,
				Number:      d.AttributeNumber,
				Name:        attrName,
				Type:        d.AttributeType,
				StringValue: strVal,
			},
		}
	}
	if err = avp.SetRawValue(p.dict, p.coder); err != nil {
		return
	}
	p.AVPs = append(p.AVPs, avp)
	return
}

func (pk *Packet) RemoteAddr() net.Addr {
	return pk.addr
}
