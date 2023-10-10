package radigo

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"sync"
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

BEGIN-VENDOR    Microsoft
ATTRIBUTE       MS-CHAP-Response                        1       octets[50]
ATTRIBUTE       MS-CHAP-Error                           2       string
ATTRIBUTE       MS-CHAP-CPW-1                           3       octets[70]
END-VENDOR Microsoft
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
			311: map[uint8]*DictionaryAttribute{
				1: &DictionaryAttribute{
					AttributeName:   "MS-CHAP-Response",
					AttributeNumber: 1,
					AttributeType:   "octets",
				},
				2: &DictionaryAttribute{
					AttributeName:   "MS-CHAP-Error",
					AttributeNumber: 2,
					AttributeType:   "string",
				},
				3: &DictionaryAttribute{
					AttributeName:   "MS-CHAP-CPW-1",
					AttributeNumber: 3,
					AttributeType:   "octets",
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
			"Microsoft": map[string]*DictionaryAttribute{
				"MS-CHAP-Response": &DictionaryAttribute{
					AttributeName:   "MS-CHAP-Response",
					AttributeNumber: 1,
					AttributeType:   "octets",
				},
				"MS-CHAP-Error": &DictionaryAttribute{
					AttributeName:   "MS-CHAP-Error",
					AttributeNumber: 2,
					AttributeType:   "string",
				},
				"MS-CHAP-CPW-1": &DictionaryAttribute{
					AttributeName:   "MS-CHAP-CPW-1",
					AttributeNumber: 3,
					AttributeType:   "octets",
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
	if err := dict.ParseFromReader(strings.NewReader(freeRADIUSDocDictSample)); err != nil {
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

func TestNewDictionaryFromFoldersWithRFC2865(t *testing.T) {
	dict, err := NewDictionaryFromFoldersWithRFC2865([]string{"dict", "dict2"})
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
	if len(dict.ac[311]) != 6 {
		t.Errorf("Expecting len: 6, received len: %d, items: %+v", len(dict.ac[311]), dict.ac[311])
	}
	if len(dict.an["Microsoft"]) != 6 {
		t.Errorf("Expecting len: 6, received len: %d, items: %+v", len(dict.an["Microsoft"]), dict.an["Microsoft"])
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

func TestDictionaryparseDictionaryAttributeInvalidValue(t *testing.T) {
	input := []string{"1", "2", "256", "4"}

	experr := fmt.Sprintf("attribute type <%d> must be lower than 255", 256)
	da, err := parseDictionaryAttribute(input)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}

	if da != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, da)
	}
}

func TestDictionaryparseDictionaryValueInvalidLen(t *testing.T) {
	input := []string{"test"}

	experr := fmt.Sprintf("invalid value definition: %v", input)
	dv, err := parseDictionaryValue(input)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}

	if dv != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, dv)
	}
}

func TestDictionaryparseDictionaryValueInvalidValue(t *testing.T) {
	input := []string{"1", "2", "3", "invalid", "5"}

	experr := fmt.Sprintf("strconv.Atoi: parsing \"%s\": invalid syntax", input[3])
	dv, err := parseDictionaryValue(input)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}

	if dv != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, dv)
	}
}

func TestDictionaryparseDictionaryVendorInvalidLen(t *testing.T) {
	input := []string{"1", "2"}

	experr := fmt.Sprintf("invalid vendor definition: %v", input)
	dvndr, err := parseDictionaryVendor(input)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}

	if dvndr != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, dvndr)
	}
}

func TestDictionaryparseDictionaryVendorInvalidValue(t *testing.T) {
	input := []string{"1", "2", "invalid"}

	experr := fmt.Sprintf("strconv.Atoi: parsing \"%s\": invalid syntax", input[2])
	dvndr, err := parseDictionaryVendor(input)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}

	if dvndr != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, dvndr)
	}
}

func TestDictionaryNewDictionaryFromFoldersWithRFC2865(t *testing.T) {
	dirPath := []string{"invalidPath"}

	experr := fmt.Sprintf("stat %s: no such file or directory", dirPath[0])
	rcv, err := NewDictionaryFromFoldersWithRFC2865(dirPath)

	if err == nil || err.Error() != experr {
		t.Fatalf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}

	if rcv != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, rcv)
	}
}

type readerMock struct {
	err error
}

func (rM *readerMock) Read(p []byte) (n int, err error) {
	rM.err = fmt.Errorf("invalid reader")
	return 0, rM.err
}

func TestDictionaryParseFromReaderFailRead(t *testing.T) {
	dict := &Dictionary{}
	reader := &readerMock{}

	experr := "invalid reader"
	err := dict.ParseFromReader(reader)

	if err == nil || err.Error() != experr {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", experr, err)
	}
}

func TestDictionaryParseFromReaderErrAttribute(t *testing.T) {
	dict := &Dictionary{}

	reader := bytes.NewBufferString(AttributeKeyword + "\n\n")
	experr := fmt.Sprintf("invalid attribute definition: [%v]", AttributeKeyword)
	explogerr := fmt.Sprintf("dictionary line: %d, <%s>", 1, experr)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	err := dict.ParseFromReader(reader)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !strings.Contains(buf.String(), explogerr) {
		t.Errorf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			explogerr,
			buf.String()[20:20+len(explogerr)],
		)
	}
}

func TestDictionaryParseFromReaderErrValue(t *testing.T) {
	dict := &Dictionary{}

	reader := bytes.NewBufferString(ValueKeyword + "\n\n")
	experr := fmt.Sprintf("invalid value definition: [%v]", ValueKeyword)
	explogerr := fmt.Sprintf("dictionary line: %d, <%s>", 1, experr)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	err := dict.ParseFromReader(reader)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !strings.Contains(buf.String(), explogerr) {
		t.Errorf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			explogerr,
			buf.String()[20:20+len(explogerr)],
		)
	}
}

func TestDictionaryParseFromReaderErrVendor(t *testing.T) {
	dict := &Dictionary{}

	reader := bytes.NewBufferString(VendorKeyword + "\n\n")
	experr := fmt.Sprintf("invalid vendor definition: [%v]", VendorKeyword)
	explogerr := fmt.Sprintf("dictionary line: %d, <%s>", 1, experr)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	err := dict.ParseFromReader(reader)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !strings.Contains(buf.String(), explogerr) {
		t.Errorf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			explogerr,
			buf.String()[20:20+len(explogerr)],
		)
	}
}

func TestDictionaryParseFromReaderErrBeginVendorLen(t *testing.T) {
	dict := &Dictionary{}

	reader := bytes.NewBufferString(BeginVendorKeyword + "\n\n")
	explogerr := fmt.Sprintf("dictionary line: %d, <mandatory inFormation missing>", 1)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	err := dict.ParseFromReader(reader)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !strings.Contains(buf.String(), explogerr) {
		t.Errorf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			explogerr,
			buf.String()[20:20+len(explogerr)],
		)
	}
}

func TestDictionaryParseFromReaderErrBeginVendorUnknown(t *testing.T) {
	dict := &Dictionary{}

	reader := bytes.NewBufferString(BeginVendorKeyword + " vendor2 vendor3" + "\n\n")
	explogerr := fmt.Sprintf("dictioanry line: %d, <unknown vendor name: %s>", 1, "vendor2")

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	err := dict.ParseFromReader(reader)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !strings.Contains(buf.String(), explogerr) {
		t.Errorf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			explogerr,
			buf.String()[20:20+len(explogerr)],
		)
	}
}

func TestDictionaryParseFromReaderErrEndVendorLen(t *testing.T) {
	dict := &Dictionary{}

	reader := bytes.NewBufferString(EndVendorKeyword + "\n\n")
	explogerr := fmt.Sprintf("dictionary line: %d, <mandatory inFormation missing>", 1)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	err := dict.ParseFromReader(reader)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !strings.Contains(buf.String(), explogerr) {
		t.Errorf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			explogerr,
			buf.String()[20:20+len(explogerr)],
		)
	}
}

func TestDictionaryParseFromReaderErrEndVendorUnknown(t *testing.T) {
	dict := &Dictionary{}

	reader := bytes.NewBufferString(EndVendorKeyword + " vendor2 vendor3" + "\n\n")
	explogerr := fmt.Sprintf("dictioanry line: %d, <unknown vendor name: %s>", 1, "vendor2")

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	err := dict.ParseFromReader(reader)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !strings.Contains(buf.String(), explogerr) {
		t.Errorf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			explogerr,
			buf.String()[20:20+len(explogerr)],
		)
	}
}

func TestDictionaryParseFromReaderErrEndVendorNotFound(t *testing.T) {
	dict := &Dictionary{
		RWMutex: sync.RWMutex{},
		vndr: &DictionaryVendor{
			VendorNumber: 1,
		},
		vn: map[string]*DictionaryVendor{
			"vendor2": {
				VendorNumber: 2,
			},
		},
	}

	reader := bytes.NewBufferString(EndVendorKeyword + " vendor2 vendor3" + "\n\n")
	explogerr := fmt.Sprintf("line: %d, <no BEGIN_VENDOR for vendor name: %s>", 1, "vendor2")

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	err := dict.ParseFromReader(reader)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !strings.Contains(buf.String(), explogerr) {
		t.Errorf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			explogerr,
			buf.String()[20:20+len(explogerr)],
		)
	}
}

func TestDictionaryParseFromReaderErrDefault(t *testing.T) {
	dict := &Dictionary{}

	reader := bytes.NewBufferString("invalid" + "\n\n")
	explogerr := fmt.Sprintf("dictionary line: %d, <unsupported keyword: %s>", 1, "invalid")

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	err := dict.ParseFromReader(reader)

	if err != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, err)
	}

	if !strings.Contains(buf.String(), explogerr) {
		t.Errorf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			explogerr,
			buf.String()[20:20+len(explogerr)],
		)
	}
}

func TestDictionaryValueWithNameNoDictValue(t *testing.T) {
	attr, val, vendor := "attrName", "valName", "vendorName"
	dict := &Dictionary{
		valName: map[string]map[string]map[string]*DictionaryValue{
			vendor: {},
		},
	}

	rcv := dict.ValueWithName(attr, val, vendor)

	if rcv != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, rcv)
	}
}

func TestDictionaryValueWithNumberNoDictValue1(t *testing.T) {
	attr := "attrName"
	val := uint8(1)
	vendor := uint32(2)
	dict := &Dictionary{
		valNr: map[uint32]map[string]map[uint8]*DictionaryValue{},
	}

	rcv := dict.ValueWithNumber(attr, val, vendor)

	if rcv != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, rcv)
	}
}

func TestDictionaryValueWithNoDictValue2(t *testing.T) {
	attr := "attrName"
	val := uint8(1)
	vendor := uint32(2)
	dict := &Dictionary{
		valNr: map[uint32]map[string]map[uint8]*DictionaryValue{
			vendor: {},
		},
	}

	rcv := dict.ValueWithNumber(attr, val, vendor)

	if rcv != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, rcv)
	}
}

func TestDictionaryNewDictionaries(t *testing.T) {
	var dicts map[string]*Dictionary

	exp := &Dictionaries{}
	rcv := NewDictionaries(dicts)

	if len(exp.dicts) != len(rcv.dicts) && len(rcv.dicts) == 0 {
		t.Fatalf(
			"\nExpected: <%+v>, \nReceived: <%+v>",
			len(exp.dicts),
			len(rcv.dicts),
		)
	}
}

func TestDictionaryGetInstance(t *testing.T) {
	dts := &Dictionaries{
		RWMutex: sync.RWMutex{},
	}
	instance := "test"

	rcv := dts.GetInstance(instance)

	if rcv != nil {
		t.Errorf("\nExpected: <%+v>, \nReceived: <%+v>", nil, rcv)
	}
}
