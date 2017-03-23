package radigo

import (
	"sync"
)

type ClientID string

// Dictionary translates between types and human readable attributes
// provides per-client information
type Dictionary struct {
	sync.RWMutex
	atAN map[ClientID]map[AttributeType]AttributeName // maps attribute type into human-readable text
	anAT map[ClientID]map[AttributeName]AttributeType // reverse maps attribute name towards attribute type
}
