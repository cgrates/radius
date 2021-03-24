package radigo

import (
	"reflect"
	"testing"

	"github.com/cgrates/radigo/codecs"
)

func TestCoderEncode(t *testing.T) {
	cdr := Coder{
		IntegerValue: codecs.IntegerCodec{},
	}
	var v interface{} = uint32(123)

	exp := []byte{0, 0, 0, 123}
	rcv, err := cdr.Encode(IntegerValue, v)
	if err != nil {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}
	if !reflect.DeepEqual(exp, rcv) {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", exp, rcv)
	}
}
