package radigo

import (
	"reflect"
	"testing"
)

func TestParseDictAttribute(t *testing.T) {
	eDA := &dictAttribute{
		attributeName:   "User-Name",
		attributeNumber: 1,
		attributeType:   "string"}
	if da, err := parseDictAttribute([]string{"ATTRIBUTE", "User-Name", "1", "string"}); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(eDA, da) {
		t.Errorf("Expecting: %+v, received: %+v", eDA, da)
	}
	if _, err := parseDictAttribute([]string{"ATTRIBUTE"}); err == nil {
		t.Error("Should have error")
	}
	if _, err := parseDictAttribute([]string{"ATTRIBUTE", "User-Name", "string", "string"}); err == nil {
		t.Error("Should have error")
	}
}

// VALUE    Framed-Protocol    PPP    1
func TestParseDictValue(t *testing.T) {
	eDV := &dictValue{
		attributeName:   "Framed-Protocol",
		valueName:       "PPP",
		attributeNumber: 1}
	if dv, err := parseDictValue([]string{"VALUE", "Framed-Protocol", "PPP", "1"}); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(eDV, dv) {
		t.Errorf("Expecting: %+v, received: %+v", eDV, dv)
	}
	if _, err := parseDictAttribute([]string{"VALUE"}); err == nil {
		t.Error("Should have error")
	}
	if _, err := parseDictAttribute([]string{"VALUE", "Framed-Protocol", "PPP", "string"}); err == nil {
		t.Error("Should have error")
	}
}
