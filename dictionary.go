package radigo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	AttributeKeyword   = "ATTRIBUTE"
	ValueKeyword       = "VALUE"
	VendorKeyword      = "VENDOR"
	BeginVendorKeyword = "BEGIN-VENDOR"
	EndVendorKeyword   = "END-VENDOR"
	IncludeFileKeyword = "$INCLUDE"
	// rfc2865 value Formats
	TextValue    = "text"
	StringValue  = "string"
	AddressValue = "address"
	IntegerValue = "integer"
	TimeValue    = "time"
	IPAddrValue  = "ipaddr"
	UnknownValue = "unknown"
)

var ErrUnsupportedAttributeType = errors.New("unsupported attribute type")

var RFC2865Dict = `
# Originally copied from FreeRADIUS dictionary

ATTRIBUTE	User-Name		1	string
ATTRIBUTE	Password		2	string
ATTRIBUTE	CHAP-Password		3	string
ATTRIBUTE	NAS-IP-Address		4	ipaddr
ATTRIBUTE	NAS-Port-Id		5	integer
ATTRIBUTE	Service-Type		6	integer
ATTRIBUTE	Framed-Protocol		7	integer
ATTRIBUTE	Framed-IP-Address	8	ipaddr
ATTRIBUTE	Framed-IP-Netmask	9	ipaddr
ATTRIBUTE	Framed-Routing		10	integer
ATTRIBUTE	Filter-Id		11	string
ATTRIBUTE	Framed-MTU		12	integer
ATTRIBUTE	Framed-Compression	13	integer
ATTRIBUTE	Login-IP-Host		14	ipaddr
ATTRIBUTE	Login-Service		15	integer
ATTRIBUTE	Login-TCP-Port		16	integer
ATTRIBUTE	Reply-Message		18	string
ATTRIBUTE	Callback-Number		19	string
ATTRIBUTE	Callback-Id		20	string
ATTRIBUTE	Framed-Route		22	string
ATTRIBUTE	Framed-IPX-Network	23	ipaddr
ATTRIBUTE	State			24	string
ATTRIBUTE	Class			25	string
ATTRIBUTE	Vendor-Specific		26	string
ATTRIBUTE	Session-Timeout		27	integer
ATTRIBUTE	Idle-Timeout		28	integer
ATTRIBUTE	Termination-Action	29	integer
ATTRIBUTE	Called-Station-Id	30	string
ATTRIBUTE	Calling-Station-Id	31	string
ATTRIBUTE	NAS-Identifier		32	string
ATTRIBUTE	Proxy-State		33	string
ATTRIBUTE	Login-LAT-Service	34	string
ATTRIBUTE	Login-LAT-Node		35	string
ATTRIBUTE	Login-LAT-Group		36	string
ATTRIBUTE	Framed-AppleTalk-Link	37	integer
ATTRIBUTE	Framed-AppleTalk-Network	38	integer
ATTRIBUTE	Framed-AppleTalk-Zone	39	string
ATTRIBUTE	Acct-Status-Type	40	integer
ATTRIBUTE	Acct-Delay-Time		41	integer
ATTRIBUTE	Acct-Input-Octets	42	integer
ATTRIBUTE	Acct-Output-Octets	43	integer
ATTRIBUTE	Acct-Session-Id		44	string
ATTRIBUTE	Acct-Authentic		45	integer
ATTRIBUTE	Acct-Session-Time	46	integer
ATTRIBUTE	Acct-Input-Packets	47	integer
ATTRIBUTE	Acct-Output-Packets	48	integer
ATTRIBUTE	Acct-Terminate-Cause	49	integer
ATTRIBUTE	Acct-Multi-Session-Id	50	string
ATTRIBUTE	Acct-Link-Count		51	integer
ATTRIBUTE	Acct-Input-Gigawords	52	integer
ATTRIBUTE	Acct-Output-Gigawords	53	integer
ATTRIBUTE	Event-Timestamp		55	integer
ATTRIBUTE	Egress-VLANID		56	string
ATTRIBUTE	Ingress-Filters		57	integer
ATTRIBUTE	Egress-VLAN-Name	58	string
ATTRIBUTE	User-Priority-Table	59	string
ATTRIBUTE	CHAP-Challenge		60	string
ATTRIBUTE	NAS-Port-Type		61	integer
ATTRIBUTE	Port-Limit		62	integer
ATTRIBUTE	Login-LAT-Port		63	integer
`

// input: ATTRIBUTE attribute-name number type
// input: one line from the reader
func parseDictionaryAttribute(input []string) (*DictionaryAttribute, error) {
	if len(input) < 4 {
		return nil, errors.New(fmt.Sprintf("invalid attribute definition: %v", input))
	}
	attrNr, err := strconv.Atoi(input[2])
	if err != nil {
		return nil, err
	} else if attrNr > 255 {
		return nil,
			fmt.Errorf("attribute type <%d> must be lower than 255", attrNr)
	}
	return &DictionaryAttribute{AttributeName: input[1],
		AttributeNumber: uint8(attrNr), AttributeType: input[3]}, nil
}

// dictionaryAttribute defines a dictionary mapping and type for an attribute.
type DictionaryAttribute struct {
	AttributeName   string
	AttributeNumber uint8
	AttributeType   string
}

// input: VALUE attribute-name value-name number
// VALUE    Framed-Protocol    PPP    1
func parseDictionaryValue(input []string) (dVal *DictionaryValue, err error) {
	if len(input) < 4 {
		return nil, errors.New(fmt.Sprintf("invalid value definition: %v", input))
	}
	valNr, err := strconv.Atoi(input[3])
	if err != nil {
		return nil, err
	}
	return &DictionaryValue{AttributeName: input[1], ValueName: input[2],
		ValueNumber: uint8(valNr)}, nil
}

// dictionaryValue defines an enumerated value for an attribute.
type DictionaryValue struct {
	AttributeName string
	ValueName     string
	ValueNumber   uint8
}

// input VENDOR vendor-name number [Format]
func parseDictionaryVendor(input []string) (dVndr *DictionaryVendor, err error) {
	if len(input) < 3 {
		return nil, errors.New(fmt.Sprintf("invalid vendor definition: %v", input))
	}
	nr, err := strconv.Atoi(input[2])
	if err != nil {
		return nil, err
	}
	dVndr = &DictionaryVendor{VendorName: input[1], VendorNumber: uint32(nr)}
	if len(input) > 3 {
		dVndr.Format = input[3]
	}
	return
}

// DictionaryVendor defines a dictionary mapping for a vendor.
type DictionaryVendor struct {
	VendorName   string
	VendorNumber uint32
	Format       string
}

// NewEmptyDictionary initializes properly the maps in the Dictionary struct
func NewEmptyDictionary() *Dictionary {
	return &Dictionary{ac: make(map[uint32]map[uint8]*DictionaryAttribute),
		an:      make(map[string]map[string]*DictionaryAttribute),
		valName: make(map[string]map[string]map[string]*DictionaryValue),
		valNr:   make(map[uint32]map[string]map[uint8]*DictionaryValue),
		vc:      make(map[uint32]*DictionaryVendor),
		vn:      make(map[string]*DictionaryVendor),
		vndr:    new(DictionaryVendor)}
}

// Dictionary data required in RFC2865
func RFC2865Dictionary() (d *Dictionary) {
	d = NewEmptyDictionary()
	d.ParseFromReader(strings.NewReader(RFC2865Dict))
	return
}

// NewDictionaryFromFolderWithDefaults parses the folder and returns the Dictionary object
// Resulting dictionary contains RFC2865 elements
func NewDictionaryFromFolderWithRFC2865(dirPath string) (*Dictionary, error) {
	dict := RFC2865Dictionary()
	if err := dict.ParseFromFolder(dirPath); err != nil {
		return nil, err
	}
	return dict, nil
}

// Dictionary translates between types and human readable attributes
// provides per-client inFormation
type Dictionary struct {
	sync.RWMutex                                                   // locks the Dictionary so we can update it on run-time
	ac           map[uint32]map[uint8]*DictionaryAttribute         // attach inFormation on vendor/attribute number
	an           map[string]map[string]*DictionaryAttribute        // attach inFormation on vendor/attribute name
	valName      map[string]map[string]map[string]*DictionaryValue // index value names
	valNr        map[uint32]map[string]map[uint8]*DictionaryValue  // index value numbers
	vc           map[uint32]*DictionaryVendor                      // index on vendor number
	vn           map[string]*DictionaryVendor                      // index on vendor name
	vndr         *DictionaryVendor                                 // active vendor number
}

// parseFromReader loops through the lines in the reader, adding info to the Dictionary
// overwrites previous data
func (dict *Dictionary) ParseFromReader(rdr io.Reader) (err error) {
	buf := bufio.NewReader(rdr)
	lnNr := 0
	for {
		lnNr += 1
		readLine, err := buf.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if strings.HasPrefix(readLine, "#") { // ignore comments
			continue
		}
		flds := strings.Fields(readLine)
		if len(flds) == 0 {
			continue
		}
		switch flds[0] {

		case AttributeKeyword:
			dAttr, err := parseDictionaryAttribute(flds)
			if err != nil {
				log.Printf("dictionary line: %d, <%s>", lnNr, err.Error())
				continue
			}
			dict.Lock()
			if _, hasIt := dict.ac[dict.vndr.VendorNumber]; !hasIt {
				dict.ac[dict.vndr.VendorNumber] = make(map[uint8]*DictionaryAttribute)
			}
			dict.ac[dict.vndr.VendorNumber][dAttr.AttributeNumber] = dAttr
			if _, hasIt := dict.an[dict.vndr.VendorName]; !hasIt {
				dict.an[dict.vndr.VendorName] = make(map[string]*DictionaryAttribute)
			}
			dict.an[dict.vndr.VendorName][dAttr.AttributeName] = dAttr
			dict.Unlock()

		case ValueKeyword:
			dVal, err := parseDictionaryValue(flds)
			if err != nil {
				log.Printf("dictionary line: %d, <%s>", lnNr, err.Error())
				continue
			}
			dict.Lock()
			if _, hasIt := dict.valName[dict.vndr.VendorName]; !hasIt {
				dict.valName[dict.vndr.VendorName] = make(map[string]map[string]*DictionaryValue)
			}
			if _, hasIt := dict.valName[dict.vndr.VendorName][dVal.AttributeName]; !hasIt {
				dict.valName[dict.vndr.VendorName][dVal.AttributeName] = make(map[string]*DictionaryValue)
			}
			dict.valName[dict.vndr.VendorName][dVal.AttributeName][dVal.ValueName] = dVal
			if _, hasIt := dict.valNr[dict.vndr.VendorNumber]; !hasIt {
				dict.valNr[dict.vndr.VendorNumber] = make(map[string]map[uint8]*DictionaryValue)
			}
			if _, hasIt := dict.valNr[dict.vndr.VendorNumber][dVal.AttributeName]; !hasIt {
				dict.valNr[dict.vndr.VendorNumber][dVal.AttributeName] = make(map[uint8]*DictionaryValue)
			}
			dict.valNr[dict.vndr.VendorNumber][dVal.AttributeName][dVal.ValueNumber] = dVal
			dict.Unlock()

		case VendorKeyword:
			dVndr, err := parseDictionaryVendor(flds)
			if err != nil {
				log.Printf("dictionary line: %d, <%s>", lnNr, err.Error())
				continue
			}
			dict.Lock()
			dict.vc[dVndr.VendorNumber] = dVndr
			dict.vn[dVndr.VendorName] = dVndr
			dict.Unlock()

		case BeginVendorKeyword:
			if len(flds) < 2 {
				log.Printf("dictionary line: %d, <mandatory inFormation missing>", lnNr)
				continue
			}
			dict.Lock()
			if dVndr, has := dict.vn[flds[1]]; !has {
				log.Printf("dictioanry line: %d, <unknown vendor name: %s>", lnNr, flds[1])
				continue
			} else {
				dict.vndr = dVndr // activate a new vendor for indexing
			}
			dict.Unlock()

		case EndVendorKeyword:
			if len(flds) < 2 {
				log.Printf("dictionary line: %d, <mandatory inFormation missing>", lnNr)
				continue
			}
			dict.Lock()
			if dVndr, has := dict.vn[flds[1]]; !has {
				log.Printf("dictioanry line: %d, <unknown vendor name: %s>", lnNr, flds[1])
				continue
			} else if dict.vndr.VendorNumber != dVndr.VendorNumber {
				log.Printf("line: %d, <no BEGIN_VENDOR for vendor name: %s>", lnNr, flds[1])
				continue
			} else {
				dict.vndr = new(DictionaryVendor)
			}
			dict.Unlock()

		case IncludeFileKeyword: // ToDo
		default:
			log.Printf("dictionary line: %d, <unsupported keyword: %s>", lnNr, flds[0])
			continue
		}
	}
	return
}

// parseFromFolder walks through the folder/subfolders and loads all dictionary.* files it finds
func (dict *Dictionary) ParseFromFolder(dirPath string) (err error) {
	fi, err := os.Stat(dirPath)
	if err != nil {
		return err
	} else if !fi.IsDir() {
		return fmt.Errorf("path: %s not a directory.", dirPath)
	}
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			return nil
		}
		dictFiles, err := filepath.Glob(filepath.Join(path, "dictionary.*"))
		if err != nil {
			return err
		}
		if dictFiles == nil { // No need of processing further since there are no config files in the folder
			return nil
		}
		for _, dictFilePath := range dictFiles {
			if file, err := os.Open(dictFilePath); err != nil {
				return err
			} else if err = dict.ParseFromReader(file); err != nil {
				return err
			}
		}
		return nil
	})
}

// DictionaryAttribute queries Dictionary for Attribute having specific number
func (dict *Dictionary) AttributeWithNumber(attrNr uint8, vendorCode uint32) *DictionaryAttribute {
	dict.RLock()
	defer dict.RUnlock()
	if _, has := dict.ac[vendorCode]; !has {
		return nil
	}
	if _, has := dict.ac[vendorCode][attrNr]; !has {
		return nil
	}
	return dict.ac[vendorCode][attrNr]
}

// DictionaryAttribute queries Dictionary for Attribute with specific name
func (dict *Dictionary) AttributeWithName(attrName, VendorName string) *DictionaryAttribute {
	dict.RLock()
	defer dict.RUnlock()
	if _, has := dict.an[VendorName]; !has {
		return nil
	}
	if _, has := dict.an[VendorName][attrName]; !has {
		return nil
	}
	return dict.an[VendorName][attrName]
}

func (dict *Dictionary) VendorWithName(VendorName string) *DictionaryVendor {
	dict.RLock()
	defer dict.RUnlock()
	return dict.vn[VendorName]
}

func (dict *Dictionary) VendorWithCode(vendorCode uint32) *DictionaryVendor {
	dict.RLock()
	defer dict.RUnlock()
	return dict.vc[vendorCode]
}

func (dict *Dictionary) ValueWithName(attrName, valName, vendorName string) (dv *DictionaryValue) {
	dict.RLock()
	defer dict.RUnlock()
	if _, has := dict.valName[vendorName]; !has {
		return
	}
	if _, has := dict.valName[vendorName][attrName]; !has {
		return
	}
	return dict.valName[vendorName][attrName][valName]
}

func (dict *Dictionary) ValueWithNumber(attrName string, valNr uint8, vendorCode uint32) (dv *DictionaryValue) {
	dict.RLock()
	defer dict.RUnlock()
	if _, has := dict.valNr[vendorCode]; !has {
		return
	}
	if _, has := dict.valNr[vendorCode][attrName]; !has {
		return
	}
	return dict.valNr[vendorCode][attrName][valNr]
}

// NewDictionaries instantiates Dictionary structure
func NewDictionaries(dicts map[string]*Dictionary) *Dictionaries {
	if dicts == nil {
		dicts = make(map[string]*Dictionary)
	}
	return &Dictionaries{dicts: dicts}
}

// Dictionaries gathers together dictionaries to be safely accessed centralized in more than one server instance
type Dictionaries struct {
	sync.RWMutex
	dicts map[string]*Dictionary
}

// GetInstance returns the Dictionary instance based on id or default one if not found
func (dts *Dictionaries) GetInstance(instanceID string) (dict *Dictionary) {
	dts.RLock()
	dict, hasKey := dts.dicts[instanceID]
	if !hasKey {
		dict = dts.dicts[MetaDefault]
	}
	dts.RUnlock()
	return
}
