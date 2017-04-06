package radigo

import (
	"reflect"
	"strings"
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

func TestParseDictVendor(t *testing.T) {
	eDV := &dictVendor{
		vendorName:   "Cisco",
		vendorNumber: 9,
	}
	if dv, err := parseDictVendor([]string{"VENDOR", "Cisco", "9"}); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(eDV, dv) {
		t.Errorf("Expecting: %+v, received: %+v", eDV, dv)
	}
	if _, err := parseDictAttribute([]string{"VENDOR"}); err == nil {
		t.Error("Should have error")
	}
	if _, err := parseDictAttribute([]string{"VENDOR", "Cisco", "string"}); err == nil {
		t.Error("Should have error")
	}
	eDV = &dictVendor{
		vendorName:   "Cisco",
		vendorNumber: 9,
		format:       "1,0",
	}
	if dv, err := parseDictVendor([]string{"VENDOR", "Cisco", "9", "1,0"}); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(eDV, dv) {
		t.Errorf("Expecting: %+v, received: %+v", eDV, dv)
	}

}

func TestParseFromReader(t *testing.T) {
	freeRADIUSDocDictSample := `
# Most of the lines are copied from freeradius documentation here:
# http://networkradius.com/doc/3.0.10/concepts/dictionary/introduction.html

# Attributes
ATTRIBUTE    User-Name    1    string
ATTRIBUTE    Password     2    string

# Alias values
VALUE    Framed-Protocol    PPP    1

# Vendors
VENDOR    Cisco    9
VENDOR    Microsoft 311

# Vendor AVPs
BEGIN-VENDOR    Cisco
ATTRIBUTE       Cisco-AVPair    1   string
ATTRIBUTE       Cisco-NAS-Port  2	string
END-VENDOR      Cisco
`
	eDict := &Dictionary{
		ac: map[uint32]map[uint8]*dictAttribute{
			NoVendor: map[uint8]*dictAttribute{
				1: &dictAttribute{
					attributeName:   "User-Name",
					attributeNumber: 1,
					attributeType:   "string",
				},
				2: &dictAttribute{
					attributeName:   "Password",
					attributeNumber: 2,
					attributeType:   "string",
				},
			},
			9: map[uint8]*dictAttribute{
				1: &dictAttribute{
					attributeName:   "Cisco-AVPair",
					attributeNumber: 1,
					attributeType:   "string",
				},
				2: &dictAttribute{
					attributeName:   "Cisco-NAS-Port",
					attributeNumber: 2,
					attributeType:   "string",
				},
			},
		},
		an: map[uint32]map[string]*dictAttribute{
			NoVendor: map[string]*dictAttribute{
				"User-Name": &dictAttribute{
					attributeName:   "User-Name",
					attributeNumber: 1,
					attributeType:   "string",
				},
				"Password": &dictAttribute{
					attributeName:   "Password",
					attributeNumber: 2,
					attributeType:   "string",
				},
			},
			9: map[string]*dictAttribute{
				"Cisco-AVPair": &dictAttribute{
					attributeName:   "Cisco-AVPair",
					attributeNumber: 1,
					attributeType:   "string",
				},
				"Cisco-NAS-Port": &dictAttribute{
					attributeName:   "Cisco-NAS-Port",
					attributeNumber: 2,
					attributeType:   "string",
				},
			},
		},
		vc: map[uint32]*dictVendor{
			9: &dictVendor{
				vendorName:   "Cisco",
				vendorNumber: 9,
			},
			311: &dictVendor{
				vendorName:   "Microsoft",
				vendorNumber: 311,
			},
		},
		vn: map[string]*dictVendor{
			"Cisco": &dictVendor{
				vendorName:   "Cisco",
				vendorNumber: 9,
			},
			"Microsoft": &dictVendor{
				vendorName:   "Microsoft",
				vendorNumber: 311,
			},
		},
		vndr: 0,
	}
	dict := NewEmptyDictionary()
	if err := dict.ParseFromReader(strings.NewReader(freeRADIUSDocDictSample)); err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(eDict, dict) {
		t.Errorf("Expecting: %+v, received: %+v", eDict, dict)
	}
}
