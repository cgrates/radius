package radigo

import (
	"log"
	//"os"
	"bufio"
	"errors"
	"io"
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

var RFC2865 = `
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

func RFC2865Dictionary() (d *Dictionary) {
	d = &Dictionary{ac: make(map[uint32]map[uint8]*dictAttribute), an: make(map[uint32]map[string]*dictAttribute),
		vc: make(map[uint32]*dictVendor), vn: make(map[string]*dictVendor)}
	return
}

/*
func ParseDictionariesFromFolder(dirPath string) (*Dictionary, error){
	dict := RFC2865Dictionary()
	fi, err := os.Stat(dirPath)
	if err != nil {
		if strings.HasSuffix(err.Error(), "no such file or directory") {
			return cfg, nil
		}
		return nil, err
	} else if !fi.IsDir() && cfgDir != utils.CONFIG_DIR { // If config dir defined, needs to exist, not checking for default
		return nil, fmt.Errorf("Path: %s not a directory.", cfgDir)
	}
	if fi.IsDir() {
		jsonFilesFound := false
		err = filepath.Walk(cfgDir, func(path string, info os.FileInfo, err error) error {
			if !info.IsDir() {
				return nil
			}
			cfgFiles, err := filepath.Glob(filepath.Join(path, "*.json"))
			if err != nil {
				return err
			}
			if cfgFiles == nil { // No need of processing further since there are no config files in the folder
				return nil
			}
			if !jsonFilesFound {
				jsonFilesFound = true
			}
		}
	}
}
*/

// Dictionary translates between types and human readable attributes
// provides per-client information
type Dictionary struct {
	sync.RWMutex                                      // locks the Dictionary so we can update it on run-time
	ac           map[uint32]map[uint8]*dictAttribute  // attach information on vendor/attribute number
	an           map[uint32]map[string]*dictAttribute // attach information on vendor/attribute name
	vc           map[uint32]*dictVendor               // index on vendor number
	vn           map[string]*dictVendor               // index on vendor name
}

// ParseFromReader loops through the lines in the reader, adding info to the Dictionary
// overwrites previous keys found
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
		flds := strings.Fields(readLine)
		if len(flds) == 0 {
			continue
		}
		switch flds[0] {
		case AttributeKeyword:
			dAttr, err := parseDictAttribute(flds)
			if err != nil {
				log.Printf("line: %d error: <%s> parsing dictionary attributes", lnNr)
				continue
			}
			dict.Lock()
			if _, hasIt := dict.ac[NoVendor]; !hasIt {
				dict.ac[NoVendor] = make(map[uint8]*dictAttribute)
			}
			dict.ac[NoVendor][dAttr.attributeNumber] = dAttr
			if _, hasIt := dict.an[NoVendor]; !hasIt {
				dict.an[NoVendor] = make(map[string]*dictAttribute)
			}
			dict.an[NoVendor][dAttr.attributeName] = dAttr
			dict.Unlock()
		case ValueKeyword:
			//dVal, err := parseDictValue(flds)
		case VendorKeyword:
			//dVndr, err := parseDictVendor(flds)
		case BeginVendorKeyword, EndVendorKeyword, IncludeFileKeyword:
		}
	}
	return
}

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

// input VENDOR vendor-name number
func parseDictVendor(input []string) (dVndr *dictVendor, err error) {
	return
}

// dictVendor defines a dictionary mapping for a vendor.
type dictVendor struct {
	vendorName   string
	vendorNumber int
}
