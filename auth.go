package radigo

import (
	"bytes"
	"crypto/md5"
)

// interface ( authentificate )

type Authenticator interface {
	Authenticate(*Packet) (*Packet, error)
}

func NewAuthenticator(*Packet) {

}

func CHAPAuthenticate(password, authenticator, chapChallenge []byte) bool {
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
