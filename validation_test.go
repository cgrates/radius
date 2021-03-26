package radigo

import (
	"fmt"
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
