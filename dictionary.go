package radigo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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
)

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
func parseDictAttribute(input []string) (*dictAttribute, error) {
	if len(input) < 4 {
		return nil, errors.New("mandatory information missing")
	}
	attrNr, err := strconv.Atoi(input[2])
	if err != nil {
		return nil, err
	}
	return &dictAttribute{attributeName: input[1],
		attributeNumber: uint8(attrNr), attributeType: input[3]}, nil
}

// dictionaryAttribute defines a dictionary mapping and type for an attribute.
type dictAttribute struct {
	attributeName   string
	attributeNumber uint8
	attributeType   string
}

// input: VALUE attribute-name value-name number
// VALUE    Framed-Protocol    PPP    1
func parseDictValue(input []string) (dVal *dictValue, err error) {
	if len(input) < 4 {
		return nil, errors.New("mandatory information missing")
	}
	attrNr, err := strconv.Atoi(input[3])
	if err != nil {
		return nil, err
	}
	return &dictValue{attributeName: input[1], valueName: input[2],
		attributeNumber: uint8(attrNr)}, nil
}

// dictionaryValue defines an enumerated value for an attribute.
type dictValue struct {
	attributeName   string
	valueName       string
	attributeNumber uint8
}

// input VENDOR vendor-name number [format]
func parseDictVendor(input []string) (dVndr *dictVendor, err error) {
	if len(input) < 3 {
		return nil, errors.New("mandatory information missing")
	}
	nr, err := strconv.Atoi(input[2])
	if err != nil {
		return nil, err
	}
	dVndr = &dictVendor{vendorName: input[1], vendorNumber: uint32(nr)}
	if len(input) > 3 {
		dVndr.format = input[3]
	}
	return
}

// dictVendor defines a dictionary mapping for a vendor.
type dictVendor struct {
	vendorName   string
	vendorNumber uint32
	format       string
}

func NewEmptyDictionary() *Dictionary {
	return &Dictionary{ac: make(map[uint32]map[uint8]*dictAttribute), an: make(map[uint32]map[string]*dictAttribute),
		vc: make(map[uint32]*dictVendor), vn: make(map[string]*dictVendor)}
}

// Dictionary translates between types and human readable attributes
// provides per-client information
type Dictionary struct {
	sync.RWMutex                                      // locks the Dictionary so we can update it on run-time
	ac           map[uint32]map[uint8]*dictAttribute  // attach information on vendor/attribute number
	an           map[uint32]map[string]*dictAttribute // attach information on vendor/attribute name
	vc           map[uint32]*dictVendor               // index on vendor number
	vn           map[string]*dictVendor               // index on vendor name
	vndr         uint32                               // active vendor number
}

// ParseFromReader loops through the lines in the reader, adding info to the Dictionary
// overwrites previous keys found
func (dict *Dictionary) parseFromReader(rdr io.Reader) (err error) {
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
			dAttr, err := parseDictAttribute(flds)
			if err != nil {
				return fmt.Errorf("line: %d, <%s>", lnNr, err.Error())
			}
			dict.Lock()
			if _, hasIt := dict.ac[dict.vndr]; !hasIt {
				dict.ac[dict.vndr] = make(map[uint8]*dictAttribute)
			}
			dict.ac[dict.vndr][dAttr.attributeNumber] = dAttr
			if _, hasIt := dict.an[dict.vndr]; !hasIt {
				dict.an[dict.vndr] = make(map[string]*dictAttribute)
			}
			dict.an[dict.vndr][dAttr.attributeName] = dAttr
			dict.Unlock()
		case ValueKeyword: // ToDo: finds use for this
		case VendorKeyword:
			dVndr, err := parseDictVendor(flds)
			if err != nil {
				return fmt.Errorf("line: %d, <%s>", lnNr, err.Error())
			}
			dict.Lock()
			dict.vc[dVndr.vendorNumber] = dVndr
			dict.vn[dVndr.vendorName] = dVndr
			dict.Unlock()
		case BeginVendorKeyword:
			if len(flds) < 2 {
				return fmt.Errorf("line: %d, <mandatory information missing>", lnNr)
			}
			dict.Lock()
			if dVndr, has := dict.vn[flds[1]]; !has {
				return fmt.Errorf("line: %d, <unknown vendor name: %s>", lnNr, flds[1])
			} else {
				dict.vndr = dVndr.vendorNumber // activate a new vendor for indexing
			}
			dict.Unlock()
		case EndVendorKeyword:
			if len(flds) < 2 {
				return fmt.Errorf("line: %d, <mandatory information missing>", lnNr)
			}
			dict.Lock()
			if dVndr, has := dict.vn[flds[1]]; !has {
				return fmt.Errorf("line: %d, <unknown vendor name: %s>", lnNr, flds[1])
			} else if dict.vndr != dVndr.vendorNumber {
				return fmt.Errorf("line: %d, <no BEGIN_VENDOR for vendor name: %s>", lnNr, flds[1])
			} else {
				dict.vndr = NoVendor
			}
			dict.Unlock()
		case IncludeFileKeyword: // ToDo
		default:
			return fmt.Errorf("line: %d, <unsupported keyword: %s>", lnNr, flds[0])
		}
	}
	return
}

func (dict *Dictionary) parseFromFolder(dirPath string) (err error) {
	fi, err := os.Stat(dirPath)
	if err != nil {
		return err
	} else if !fi.IsDir() {
		return fmt.Errorf("path: %s not a directory.", dirPath)
	}
	var fileFound bool
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
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
		fileFound = true
		for _, dictFilePath := range dictFiles {
			if file, err := os.Open(dictFilePath); err != nil {
				return err
			} else if err = dict.parseFromReader(file); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	} else if !fileFound {
		return fmt.Errorf("no dictionary file on path <%s>", dirPath)
	}
	return nil
}

// Dictionary data required in RFC2865
func RFC2865Dictionary() (d *Dictionary) {
	d = NewEmptyDictionary()
	d.parseFromReader(strings.NewReader(RFC2865Dict))
	return
}
