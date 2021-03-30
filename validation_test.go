package radigo

import (
	"crypto/md5"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
)

func TestValidationValidateLongValue(t *testing.T) {
	v := Validation{
		MinLength: 0,
	}
	attr := &AVP{
		RawValue: []byte{1},
	}
	p := &Packet{}

	experr := fmt.Sprintf("value too long for : %+v", attr)
	err := v.Validate(p, attr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestValidationValidateDecode(t *testing.T) {
	v := Validation{
		MinLength: 0,
		MaxLength: 2,
		Decode:    DecodeUserPassword,
	}
	attr := &AVP{
		RawValue: []byte{1},
	}
	p := &Packet{}

	experr := "empty secret"
	err := v.Validate(p, attr)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestValidationDecodeUserPassword1(t *testing.T) {
	p := &Packet{
		secret: "nonempty",
	}
	a := &AVP{
		RawValue: []byte{
			0, 2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6,
			6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8},
	}

	exp := []byte{
		118, 92, 8, 36, 69, 208, 202, 142, 97, 114, 194, 148,
		8, 37, 168, 182, 63, 59, 66, 86, 140, 253, 145, 67,
		226, 180, 228, 129, 85, 168, 237, 169}
	err := DecodeUserPassword(p, a)
	if err != nil {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !reflect.DeepEqual(exp, a.RawValue) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, a.RawValue)
	}
}

func TestValidationDecodeUserPassword2(t *testing.T) {
	p := &Packet{
		secret: "testSecret",
	}
	a := &AVP{
		RawValue: []byte{70, 1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 5},
	}

	exp := []byte{0, 142, 238, 199, 245, 56, 149, 98, 25, 89, 74, 206, 80, 40, 113, 42}
	err := DecodeUserPassword(p, a)
	if err != nil {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !reflect.DeepEqual(exp, a.RawValue) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, a.RawValue)
	}
}

func TestValidationEncodeUserPassword(t *testing.T) {
	plaintext := []byte{
		0, 1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6,
		6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8}
	secret := []byte("encKey")
	var requestAuthenticator []byte

	exp := []byte{
		226, 208, 45, 207, 15, 37, 78, 236, 65, 229, 29, 215, 17, 0,
		181, 221, 198, 34, 119, 149, 128, 228, 244, 129, 211, 121, 23,
		32, 210, 99, 255, 185}
	rcv := EncodeUserPassword(plaintext, secret, requestAuthenticator)

	if !reflect.DeepEqual(rcv, exp) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestValidationAuthenticateCHAP1(t *testing.T) {
	pw := []byte{}
	auth := []byte{}
	chapChallenge := []byte{1}

	rcv := AuthenticateCHAP(pw, auth, chapChallenge)

	if rcv != false {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", false, rcv)
	}
}

func TestValidationAuthenticateCHAP2(t *testing.T) {
	pw := []byte{}
	auth := []byte{}
	chapChallenge := []byte{0, 1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 5, 6}

	rcv := AuthenticateCHAP(pw, auth, chapChallenge)

	if rcv != false {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", false, rcv)
	}
}

func TestValidationAuthenticateCHAP3(t *testing.T) {
	pw := []byte{}
	auth := []byte{}
	chapChallenge := []byte{
		1, 85, 165, 64, 8, 173, 27, 165, 137, 170,
		33, 13, 38, 41, 193, 223, 65}

	rcv := AuthenticateCHAP(pw, auth, chapChallenge)

	if rcv != true {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", true, rcv)
	}
}

func TestValidationEncodeCHAPPassword(t *testing.T) {
	rand.Seed(10)

	pw := []byte("passwd")
	auth := []byte("authenticator")

	rcv := EncodeCHAPPassword(pw, auth)
	h := md5.New()
	h.Write(rcv[:1])
	h.Write(pw)
	h.Write(auth)
	exp := make([]byte, 17)
	exp[0] = rcv[0]
	copy(exp[1:], h.Sum(nil))

	if !reflect.DeepEqual(rcv, exp) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestValidationisAuthenticReq(t *testing.T) {
	request := []byte("tooshort")
	secret := []byte("secret")

	rcv := isAuthenticReq(request, secret)

	if rcv != false {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", false, rcv)
	}
}

func TestValidationToUTF16(t *testing.T) {
	in := "testString"

	exp := []byte{
		116, 0, 101, 0, 115, 0, 116, 0, 83, 0, 116,
		0, 114, 0, 105, 0, 110, 0, 103, 0}
	rcv, err := ToUTF16(in)

	if err != nil {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !reflect.DeepEqual(rcv, exp) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestValidationGenerateNTResponseSuccess(t *testing.T) {
	authChallenge := []byte{}
	peerChallenge := []byte{}
	user := "username"
	pw := "password"

	exp := []byte{
		123, 88, 151, 34, 244, 180, 60, 222, 168, 209, 242, 98, 42,
		114, 222, 214, 222, 152, 69, 162, 219, 31, 15, 165}
	rcv, err := GenerateNTResponse(authChallenge, peerChallenge, user, pw)

	if err != nil {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !reflect.DeepEqual(rcv, exp) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestValidationDESCrypt(t *testing.T) {
	key := []byte("key")
	clear := []byte("")
	defer func() {
		exp := "crypto/des: invalid key size 3"
		r := recover()

		if r == nil {
			t.Error("Expected to panic")
		}

		if r != nil {
			rcv := r.(error)
			if rcv.Error() != exp {
				t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
			}
		}
	}()
	DESCrypt(key, clear)
}

func TestValidationGenerateAuthenticatorResponseSuccess(t *testing.T) {
	authChallenge := []byte{1}
	peerChallenge := []byte{2}
	ntResponse := []byte{3}
	user := "username"
	pw := "password"

	exp := "S=D56A5E06001F661A2B92640F3A560F5512EC0B35"
	rcv, err := GenerateAuthenticatorResponse(authChallenge, peerChallenge, ntResponse, user, pw)

	if err != nil {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if rcv != exp {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}

func TestValidationGenerateClientMSCHAPResponseSuccess(t *testing.T) {

	auth := [16]byte{0, 1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 5}
	user := "username"
	pw := "password"

	exp := make([]byte, 50)
	rcv, err := GenerateClientMSCHAPResponse(auth, user, pw)
	exp[0] = rcv[0]
	copy(exp[2:18], rcv[2:18])
	copy(exp[26:50], rcv[26:50])

	if err != nil {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !reflect.DeepEqual(rcv, exp) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}
