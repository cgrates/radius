package radigo

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseDictionaryAttribute(t *testing.T) {
	eDA := &DictionaryAttribute{
		AttributeName:   "User-Name",
		AttributeNumber: 1,
		AttributeType:   "string"}
	if da, err := parseDictionaryAttribute([]string{"ATTRIBUTE", "User-Name", "1", "string"}); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(eDA, da) {
		t.Errorf("Expecting: %+v, received: %+v", eDA, da)
	}
	if _, err := parseDictionaryAttribute([]string{"ATTRIBUTE"}); err == nil {
		t.Error("Should have error")
	}
	if _, err := parseDictionaryAttribute([]string{"ATTRIBUTE", "User-Name", "string", "string"}); err == nil {
		t.Error("Should have error")
	}
}

func TestParseDictValue(t *testing.T) {
	eDV := &DictionaryValue{
		AttributeName: "Framed-Protocol",
		ValueName:     "PPP",
		ValueNumber:   1}
	if dv, err := parseDictionaryValue([]string{"VALUE", "Framed-Protocol", "PPP", "1"}); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(eDV, dv) {
		t.Errorf("Expecting: %+v, received: %+v", eDV, dv)
	}
	if _, err := parseDictionaryAttribute([]string{"VALUE"}); err == nil {
		t.Error("Should have error")
	}
	if _, err := parseDictionaryAttribute([]string{"VALUE", "Framed-Protocol", "PPP", "string"}); err == nil {
		t.Error("Should have error")
	}
}

func TestParseDictionaryVendor(t *testing.T) {
	eDV := &DictionaryVendor{
		VendorName:   "Cisco",
		VendorNumber: 9,
	}
	if dv, err := parseDictionaryVendor([]string{"VENDOR", "Cisco", "9"}); err != nil {
		t.Error(err)
	} else if !reflect.DeepEqual(eDV, dv) {
		t.Errorf("Expecting: %+v, received: %+v", eDV, dv)
	}
	if _, err := parseDictionaryAttribute([]string{"VENDOR"}); err == nil {
		t.Error("Should have error")
	}
	if _, err := parseDictionaryAttribute([]string{"VENDOR", "Cisco", "string"}); err == nil {
		t.Error("Should have error")
	}
	eDV = &DictionaryVendor{
		VendorName:   "Cisco",
		VendorNumber: 9,
		Format:       "1,0",
	}
	if dv, err := parseDictionaryVendor([]string{"VENDOR", "Cisco", "9", "1,0"}); err != nil {
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
		ac: map[uint32]map[uint8]*DictionaryAttribute{
			NoVendor: map[uint8]*DictionaryAttribute{
				1: &DictionaryAttribute{
					AttributeName:   "User-Name",
					AttributeNumber: 1,
					AttributeType:   "string",
				},
				2: &DictionaryAttribute{
					AttributeName:   "Password",
					AttributeNumber: 2,
					AttributeType:   "string",
				},
			},
			9: map[uint8]*DictionaryAttribute{
				1: &DictionaryAttribute{
					AttributeName:   "Cisco-AVPair",
					AttributeNumber: 1,
					AttributeType:   "string",
				},
				2: &DictionaryAttribute{
					AttributeName:   "Cisco-NAS-Port",
					AttributeNumber: 2,
					AttributeType:   "string",
				},
			},
		},
		an: map[string]map[string]*DictionaryAttribute{
			"": map[string]*DictionaryAttribute{
				"User-Name": &DictionaryAttribute{
					AttributeName:   "User-Name",
					AttributeNumber: 1,
					AttributeType:   "string",
				},
				"Password": &DictionaryAttribute{
					AttributeName:   "Password",
					AttributeNumber: 2,
					AttributeType:   "string",
				},
			},
			"Cisco": map[string]*DictionaryAttribute{
				"Cisco-AVPair": &DictionaryAttribute{
					AttributeName:   "Cisco-AVPair",
					AttributeNumber: 1,
					AttributeType:   "string",
				},
				"Cisco-NAS-Port": &DictionaryAttribute{
					AttributeName:   "Cisco-NAS-Port",
					AttributeNumber: 2,
					AttributeType:   "string",
				},
			},
		},
		valName: map[string]map[string]map[string]*DictionaryValue{
			"": map[string]map[string]*DictionaryValue{
				"Framed-Protocol": map[string]*DictionaryValue{
					"PPP": &DictionaryValue{
						AttributeName: "Framed-Protocol",
						ValueName:     "PPP",
						ValueNumber:   1,
					},
				},
			},
		},
		valNr: map[uint32]map[string]map[uint8]*DictionaryValue{
			NoVendor: map[string]map[uint8]*DictionaryValue{
				"Framed-Protocol": map[uint8]*DictionaryValue{
					1: &DictionaryValue{
						AttributeName: "Framed-Protocol",
						ValueName:     "PPP",
						ValueNumber:   1,
					},
				},
			},
		},
		vc: map[uint32]*DictionaryVendor{
			9: &DictionaryVendor{
				VendorName:   "Cisco",
				VendorNumber: 9,
			},
			311: &DictionaryVendor{
				VendorName:   "Microsoft",
				VendorNumber: 311,
			},
		},
		vn: map[string]*DictionaryVendor{
			"Cisco": &DictionaryVendor{
				VendorName:   "Cisco",
				VendorNumber: 9,
			},
			"Microsoft": &DictionaryVendor{
				VendorName:   "Microsoft",
				VendorNumber: 311,
			},
		},
		vndr: new(DictionaryVendor),
	}
	dict := NewEmptyDictionary()
	if err := dict.parseFromReader(strings.NewReader(freeRADIUSDocDictSample)); err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(eDict, dict) {
		t.Errorf("Expecting: %+v, received: %+v", eDict, dict)
	}
}

func TestDictionaryQueries(t *testing.T) {
	dict := &Dictionary{
		ac: map[uint32]map[uint8]*DictionaryAttribute{
			NoVendor: map[uint8]*DictionaryAttribute{
				1: &DictionaryAttribute{
					AttributeName:   "User-Name",
					AttributeNumber: 1,
					AttributeType:   "string",
				},
				2: &DictionaryAttribute{
					AttributeName:   "Password",
					AttributeNumber: 2,
					AttributeType:   "string",
				},
			},
			9: map[uint8]*DictionaryAttribute{
				1: &DictionaryAttribute{
					AttributeName:   "Cisco-AVPair",
					AttributeNumber: 1,
					AttributeType:   "string",
				},
				2: &DictionaryAttribute{
					AttributeName:   "Cisco-NAS-Port",
					AttributeNumber: 2,
					AttributeType:   "string",
				},
			},
		},
		an: map[string]map[string]*DictionaryAttribute{
			"": map[string]*DictionaryAttribute{
				"User-Name": &DictionaryAttribute{
					AttributeName:   "User-Name",
					AttributeNumber: 1,
					AttributeType:   "string",
				},
				"Password": &DictionaryAttribute{
					AttributeName:   "Password",
					AttributeNumber: 2,
					AttributeType:   "string",
				},
			},
			"Cisco": map[string]*DictionaryAttribute{
				"Cisco-AVPair": &DictionaryAttribute{
					AttributeName:   "Cisco-AVPair",
					AttributeNumber: 1,
					AttributeType:   "string",
				},
				"Cisco-NAS-Port": &DictionaryAttribute{
					AttributeName:   "Cisco-NAS-Port",
					AttributeNumber: 2,
					AttributeType:   "string",
				},
			},
		},
		vc: map[uint32]*DictionaryVendor{
			9: &DictionaryVendor{
				VendorName:   "Cisco",
				VendorNumber: 9,
			},
			311: &DictionaryVendor{
				VendorName:   "Microsoft",
				VendorNumber: 311,
			},
		},
		vn: map[string]*DictionaryVendor{
			"Cisco": &DictionaryVendor{
				VendorName:   "Cisco",
				VendorNumber: 9,
			},
			"Microsoft": &DictionaryVendor{
				VendorName:   "Microsoft",
				VendorNumber: 311,
			},
		},
		vndr: new(DictionaryVendor),
	}
	eDA := &DictionaryAttribute{
		AttributeName:   "User-Name",
		AttributeNumber: 1,
		AttributeType:   "string",
	}
	if da := dict.AttributeWithNumber(1, 0); da == nil {
		t.Error("no attribute found")
	} else if !reflect.DeepEqual(eDA, da) {
		t.Errorf("Expecting: %+v, received: %+v", eDA, da)
	}
	if da := dict.AttributeWithNumber(10, 0); da != nil {
		t.Error("should find no attribute")
	}
	if da := dict.AttributeWithNumber(10, 1); da != nil {
		t.Error("should find no attribute")
	}
	eDA = &DictionaryAttribute{
		AttributeName:   "Cisco-AVPair",
		AttributeNumber: 1,
		AttributeType:   "string",
	}
	if da := dict.AttributeWithNumber(1, 9); da == nil {
		t.Error("no attribute found")
	} else if !reflect.DeepEqual(eDA, da) {
		t.Errorf("Expecting: %+v, received: %+v", eDA, da)
	}
	eDA = &DictionaryAttribute{
		AttributeName:   "Password",
		AttributeNumber: 2,
		AttributeType:   "string",
	}
	if da := dict.AttributeWithName("Password", ""); da == nil {
		t.Error("no attribute found")
	} else if !reflect.DeepEqual(eDA, da) {
		t.Errorf("Expecting: %+v, received: %+v", eDA, da)
	}
	if da := dict.AttributeWithName("NonExistent", ""); da != nil {
		t.Error("should find no attribute")
	}
	if da := dict.AttributeWithName("Password", "NonExistent"); da != nil {
		t.Error("should find no attribute")
	}
	eDA = &DictionaryAttribute{
		AttributeName:   "Cisco-NAS-Port",
		AttributeNumber: 2,
		AttributeType:   "string",
	}
	if da := dict.AttributeWithName("Cisco-NAS-Port", "Cisco"); da == nil {
		t.Error("no attribute found")
	} else if !reflect.DeepEqual(eDA, da) {
		t.Errorf("Expecting: %+v, received: %+v", eDA, da)
	}
	eDV := &DictionaryVendor{
		VendorName:   "Cisco",
		VendorNumber: 9,
	}
	if dv := dict.VendorWithCode(9); dv == nil {
		t.Error("no vendor found")
	} else if !reflect.DeepEqual(eDV, dv) {
		t.Errorf("Expecting: %+v, received: %+v", eDV, dv)
	}
	if dv := dict.VendorWithCode(7); dv != nil {
		t.Error("vendor found")
	}
	if dv := dict.VendorWithName("Cisco"); dv == nil {
		t.Error("no vendor found")
	} else if !reflect.DeepEqual(eDV, dv) {
		t.Errorf("Expecting: %+v, received: %+v", eDV, dv)
	}
	if dv := dict.VendorWithName("SomeOther"); dv != nil {
		t.Error("vendor found")
	}
}

func TestNewDictionaryFromFolderWithRFC2865(t *testing.T) {
	dict, err := NewDictionaryFromFolderWithRFC2865("dict")
	if err != nil {
		t.Error(err)
	}
	if len(dict.ac[NoVendor]) != 62 {
		t.Errorf("Expecting len: 62, received len: %d, items: %+v", len(dict.ac[NoVendor]), dict.ac[NoVendor])
	}
	if len(dict.an[""]) != 62 {
		t.Errorf("Expecting len: 62, received len: %d, items: %+v", len(dict.an[""]), dict.an[""])
	}
	if len(dict.ac[9]) != 2 {
		t.Errorf("Expecting len: 2, received len: %d, items: %+v", len(dict.ac[9]), dict.ac[9])
	}
	if len(dict.an["Cisco"]) != 2 {
		t.Errorf("Expecting len: 2, received len: %d, items: %+v", len(dict.an["Cisco"]), dict.an["Cisco"])
	}
	if len(dict.vc) != 2 {
		t.Errorf("Expecting len: 2, received len: %d, items: %+v", len(dict.vc), dict.vc)
	}
	if len(dict.vn) != 2 {
		t.Errorf("Expecting len: 2, received len: %d, items: %+v", len(dict.vn), dict.vn)
	}
	if dict.vndr.VendorNumber != 0 {
		t.Error(dict.vndr)
	}
}
