package radigo

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
)

const (
	UNLIMITED = -1
)

type Validation struct {
	MinLength int
	MaxLength int //if < 0 unlimited
	Decode    func(p *Packet, attr *AVP) error
}

func (v Validation) Validate(p *Packet, attr *AVP) error {

	if len(attr.RawValue) < v.MinLength {
		return errors.New(fmt.Sprintf("value too short for : %+v", attr))
	}

	if v.MaxLength != UNLIMITED && len(attr.RawValue) > v.MaxLength {
		return errors.New(fmt.Sprintf("value too long for : %+v", attr))
	}

	if v.Decode != nil {
		return v.Decode(p, attr)
	}
	return nil
}

func DecodeUserPassword(p *Packet, a *AVP) error {
	//Decode password. XOR against md5(p.server.secret+Authenticator)
	secAuth := append([]byte(nil), []byte(p.secret)...)
	secAuth = append(secAuth, p.Authenticator[:]...)
	m := crypto.Hash(crypto.MD5).New()
	m.Write(secAuth)
	md := m.Sum(nil)
	pass := a.RawValue
	if len(pass) == 16 {
		for i := 0; i < len(pass); i++ {
			pass[i] = pass[i] ^ md[i]
		}
		a.RawValue = bytes.TrimRight(pass, string([]rune{0}))
		return nil
	}
	return errors.New("not implemented for password > 16")
}

var validation = map[uint8]Validation{
	1: {1, UNLIMITED, nil},           //UserName
	2: {16, 128, DecodeUserPassword}, //UserPassword
	3: {17, 17, nil},                 //CHAPPassword
	4: {4, 4, nil},                   //NASIPAddress
	5: {1, 4, nil},                   //NASPort
}
