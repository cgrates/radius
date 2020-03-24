package radigo

import (
	"bytes"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strings"

	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
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

func EncodeUserPassWord(plaintext, secret, requestAuthenticator []byte) []byte {
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

//AuthenticateCHAP receive the password as plaintext and verify against the chap challenge
func AuthenticateCHAP(password, authenticator, chapChallenge []byte) bool {
	h := md5.New()
	h.Write(chapChallenge[:1])
	h.Write(password)
	h.Write(authenticator)
	answer := h.Sum(nil)
	if len(answer) != len(chapChallenge[1:]) {
		return false
	}
	for i := range answer {
		if answer[i] != chapChallenge[i+1] {
			return false
		}
	}
	return true
}

//EncodeCHAPPassword is used in test to encode CHAP-Password raw value
func EncodeCHAPPassword(password, authenticator []byte) []byte {
	chapIdent := make([]byte, 1)
	rand.Read(chapIdent)
	h := md5.New()
	h.Write(chapIdent)
	h.Write(password)
	h.Write(authenticator)
	chapRawVal := make([]byte, 17)
	copy(chapRawVal[:1], chapIdent)
	copy(chapRawVal[1:], h.Sum(nil))
	return chapRawVal
}

// isAuthenticReq returns if the given RADIUS request is an authentic
// request using the given secret.
// for the moment we can only authenticate the AccountingRequest
func isAuthenticReq(request, secret []byte) bool {
	if len(request) < 20 || len(secret) == 0 {
		return false
	}
	pCode := PacketCode(request[0])
	switch pCode {
	case AccountingRequest:
		hash := md5.New()
		hash.Write(request[:4])
		var nul [16]byte
		hash.Write(nul[:])
		hash.Write(request[20:])
		hash.Write(secret)
		var sum [md5.Size]byte
		return bytes.Equal(hash.Sum(sum[:0]), request[4:20])
	default:
		return true
	}
}

// ToUTF16 takes an ASCII string and turns it into a UCS-2 / UTF-16 representation
func ToUTF16(in string) ([]byte, error) {
	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	pwd, err := encoder.Bytes([]byte(in))
	if err != nil {
		return []byte{}, err
	}

	return pwd, nil
}

// GenerateNTResponse - rfc2759, 8.1
func GenerateNTResponse(authenticatorChallenge, peerChallenge []byte, username, password string) ([]byte, error) {
	challenge := ChallengeHash(peerChallenge, authenticatorChallenge, username)
	ucs2Password, err := ToUTF16(password)
	if err != nil {
		return []byte{}, err
	}
	passwordHash := HashPassword(ucs2Password)

	return ChallengeResponse(challenge, passwordHash), nil
}

// ChallengeHash - rfc2759, 8.2
func ChallengeHash(peerChallenge, authenticatorChallenge []byte, username string) []byte {
	sha := sha1.New()
	sha.Write(peerChallenge)
	sha.Write(authenticatorChallenge)
	sha.Write([]byte(username))
	return sha.Sum(nil)[:8]
}

// HashPassword with MD4 - rfc2759, 8.3
func HashPassword(password []byte) []byte {
	h := md4.New()
	h.Write(password)
	return h.Sum(nil)
}

// ChallengeResponse - rfc2759, 8.5
func ChallengeResponse(challenge, passwordHash []byte) []byte {
	zPasswordHash := make([]byte, 21)
	copy(zPasswordHash, passwordHash)

	challengeResponse := make([]byte, 24)
	copy(challengeResponse[0:], DESCrypt(zPasswordHash[0:7], challenge))
	copy(challengeResponse[8:], DESCrypt(zPasswordHash[7:14], challenge))
	copy(challengeResponse[16:], DESCrypt(zPasswordHash[14:21], challenge))

	return challengeResponse
}

// parityPadDESKey transforms a 7-octet key into an 8-octed one by
// adding a parity at every 8th bit position.
// See https://limbenjamin.com/articles/des-key-parity-bit-calculator.html
func parityPadDESKey(inBytes []byte) []byte {
	in := uint64(0)
	outBytes := make([]byte, 8)

	for i := 0; i < len(inBytes); i++ {
		offset := uint64(8 * (len(inBytes) - i - 1))
		in |= uint64(inBytes[i]) << offset
	}

	for i := 0; i < len(outBytes); i++ {
		offset := uint64(7 * (len(outBytes) - i - 1))
		outBytes[i] = byte(in>>offset) << 1

		if bits.OnesCount(uint(outBytes[i]))%2 == 0 {
			outBytes[i] |= 1
		}
	}

	return outBytes
}

// DESCrypt - rfc2759, 8.6
func DESCrypt(key, clear []byte) []byte {
	k := key
	if len(k) == 7 {
		k = parityPadDESKey(key)
	}

	des, err := des.NewCipher(k)
	if err != nil {
		panic(err)
	}

	b := make([]byte, 8)
	des.Encrypt(b, clear)

	return b
}

// GenerateAuthenticatorResponse - rfc2759, 8.7
func GenerateAuthenticatorResponse(authenticatorChallenge, peerChallenge, ntResponse []byte, username, password string) (string, error) {
	ucs2Password, err := ToUTF16(password)
	if err != nil {
		return "", err
	}

	passwordHash := HashPassword(ucs2Password)
	passwordHashHash := HashPassword(passwordHash)

	magic1 := []byte{
		0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
		0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
		0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
		0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74}
	magic2 := []byte{
		0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
		0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
		0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
		0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
		0x6E}

	sha := sha1.New()
	sha.Write(passwordHashHash)
	sha.Write(ntResponse)
	sha.Write(magic1)
	digest := sha.Sum(nil)

	challenge := ChallengeHash(peerChallenge, authenticatorChallenge, username)

	sha = sha1.New()
	sha.Write(digest)
	sha.Write(challenge)
	sha.Write(magic2)
	digest = sha.Sum(nil)

	return fmt.Sprintf("S=%s", strings.ToUpper(hex.EncodeToString(digest))), nil
}

func GenerateClientMSCHAPResponse(authenticator [16]byte, userName, password string) ([]byte, error) {
	// generate the Ident
	chapIdent := make([]byte, 1)
	rand.Read(chapIdent)
	// generate 16 bytes peer Chalange
	peerChallenge := make([]byte, 16)
	rand.Read(peerChallenge)
	// compose challenge from peerChallenge, authenticator and userName
	challenge := ChallengeHash(peerChallenge, authenticator[:], userName)
	ucs2Password, err := ToUTF16(password)
	if err != nil {
		return nil, err
	}
	passwordHash := HashPassword(ucs2Password)
	// compose peerResponse
	peerResp := ChallengeResponse(challenge, passwordHash)
	respVal := make([]byte, 50)
	copy(respVal[:1], chapIdent)
	copy(respVal[2:18], peerChallenge)
	copy(respVal[26:50], peerResp)
	return respVal, nil
}
