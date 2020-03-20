package radigo

import (
	"bytes"
	"crypto/md5"
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
	if len(p.secret) == 0 {
		return errors.New("empty secret")
	}

	dec := make([]byte, 0, len(a.RawValue))

	hash := md5.New()
	hash.Write([]byte(p.secret))
	hash.Write(p.Authenticator[:])
	dec = hash.Sum(dec)

	for i, b := range a.RawValue[:16] {
		dec[i] ^= b
	}

	for i := 16; i < len(a.RawValue); i += 16 {
		hash.Reset()
		hash.Write([]byte(p.secret))
		hash.Write(a.RawValue[i-16 : i])
		dec = hash.Sum(dec)

		for j, b := range a.RawValue[i : i+16] {
			dec[i+j] ^= b
		}
	}

	if i := bytes.IndexByte(dec, 0); i > -1 {
		a.RawValue = dec[:i]
	}
	a.RawValue = dec
	return nil

}

var validation = map[uint8]Validation{
	1: {1, UNLIMITED, nil},           //UserName
	2: {16, 128, DecodeUserPassword}, //UserPassword
	3: {17, 17, nil},                 //CHAPPassword
	4: {4, 4, nil},                   //NASIPAddress
	5: {1, 4, nil},                   //NASPort
}

func EncodePass(plaintext, secret, requestAuthenticator []byte) []byte {
	chunks := (len(plaintext) + 16 - 1) / 16
	if chunks == 0 {
		chunks = 1
	}
	enc := make([]byte, 0, chunks*16)
	hash := md5.New()
	hash.Write(secret)
	hash.Write(requestAuthenticator)
	enc = hash.Sum(enc)
	for i, b := range plaintext[:16] {
		enc[i] ^= b
	}
	for i := 16; i < len(plaintext); i += 16 {
		hash.Reset()
		hash.Write(secret)
		hash.Write(enc[i-16 : i])
		enc = hash.Sum(enc)

		for j, b := range plaintext[i : i+16] {
			enc[i+j] ^= b
		}
	}
	return enc
}
