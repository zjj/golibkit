// forkd from go pkix.go
package pkixx

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
)

type RelativeDistinguishedNameSET []AttributeTypeAndValue

// AttributeTypeAndValue mirrors the ASN.1 structure of the same name in
// RFC 5280, Section 4.1.2.4.
type AttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

type RDNSequence []RelativeDistinguishedNameSET

type MyRDNSequence struct {
	Sequence           RDNSequence
	AttributeTypeNames map[string]string
}

func (mr *MyRDNSequence) SetAttributeTypeName(m map[string]string) {
	mr.AttributeTypeNames = m
}

// String returns a string representation of the sequence r,
// roughly following the RFC 2253 Distinguished Names syntax.
func (mr MyRDNSequence) String() string {
	s := ""
	r := mr.Sequence
	for i := 0; i < len(r); i++ {
		rdn := r[len(r)-1-i]
		if i > 0 {
			s += ","
		}
		for j, tv := range rdn {
			if j > 0 {
				s += "+"
			}

			oidString := tv.Type.String()
			typeName, ok := mr.AttributeTypeNames[oidString]
			if !ok {
				derBytes, err := asn1.Marshal(tv.Value)
				if err == nil {
					s += oidString + "=#" + hex.EncodeToString(derBytes)
					continue // No value escaping necessary.
				}

				typeName = oidString
			}

			valueString := fmt.Sprint(tv.Value)
			escaped := make([]rune, 0, len(valueString))

			for k, c := range valueString {
				escape := false

				switch c {
				case ',', '+', '"', '\\', '<', '>', ';':
					escape = true

				case ' ':
					escape = k == 0 || k == len(valueString)-1

				case '#':
					escape = k == 0
				}

				if escape {
					escaped = append(escaped, '\\', c)
				} else {
					escaped = append(escaped, c)
				}
			}

			s += typeName + "=" + string(escaped)
		}
	}

	return s
}

// AttributeTypeAndValueSET represents a set of ASN.1 sequences of
// AttributeTypeAndValue sequences from RFC 2986 (PKCS #10).
type AttributeTypeAndValueSET struct {
	Type  asn1.ObjectIdentifier
	Value [][]AttributeTypeAndValue `asn1:"set"`
}

// Name represents an X.509 distinguished name. This only includes the common
// elements of a DN. When parsing, all elements are stored in Names and
// non-standard elements can be extracted from there. When marshaling, elements
// in ExtraNames are appended and override other values with the same OID.
type Name struct {
	Country, Organization, OrganizationalUnit []string
	Locality, Province                        []string
	StreetAddress, PostalCode                 []string
	SerialNumber, CommonName                  string

	Names      []AttributeTypeAndValue
	ExtraNames []AttributeTypeAndValue
}

var (
	oidCountry            = []int{2, 5, 4, 6}
	oidOrganization       = []int{2, 5, 4, 10}
	oidOrganizationalUnit = []int{2, 5, 4, 11}
	oidCommonName         = []int{2, 5, 4, 3}
	oidSerialNumber       = []int{2, 5, 4, 5}
	oidLocality           = []int{2, 5, 4, 7}
	oidProvince           = []int{2, 5, 4, 8}
	oidStreetAddress      = []int{2, 5, 4, 9}
	oidPostalCode         = []int{2, 5, 4, 17}
)

// oidInAttributeTypeAndValue reports whether a type with the given OID exists
// in atv.
func oidInAttributeTypeAndValue(oid asn1.ObjectIdentifier, atv []AttributeTypeAndValue) bool {
	for _, a := range atv {
		if a.Type.Equal(oid) {
			return true
		}
	}
	return false
}

// appendRDNs appends a relativeDistinguishedNameSET to the given RDNSequence
// and returns the new value. The relativeDistinguishedNameSET contains an
// attributeTypeAndValue for each of the given values. See RFC 5280, A.1, and
// search for AttributeTypeAndValue.
func (n Name) appendRDNs(in RDNSequence, values []string, oid asn1.ObjectIdentifier) RDNSequence {
	if len(values) == 0 || oidInAttributeTypeAndValue(oid, n.ExtraNames) {
		return in
	}

	s := make([]AttributeTypeAndValue, len(values))
	for i, value := range values {
		s[i].Type = oid
		s[i].Value = value
	}

	return append(in, s)
}

func (n Name) ToRDNSequence() MyRDNSequence {
	ret := RDNSequence{}
	ret = n.appendRDNs(ret, n.Country, oidCountry)
	ret = n.appendRDNs(ret, n.Province, oidProvince)
	ret = n.appendRDNs(ret, n.Locality, oidLocality)
	ret = n.appendRDNs(ret, n.StreetAddress, oidStreetAddress)
	ret = n.appendRDNs(ret, n.PostalCode, oidPostalCode)
	ret = n.appendRDNs(ret, n.Organization, oidOrganization)
	ret = n.appendRDNs(ret, n.OrganizationalUnit, oidOrganizationalUnit)
	if len(n.CommonName) > 0 {
		ret = n.appendRDNs(ret, []string{n.CommonName}, oidCommonName)
	}
	if len(n.SerialNumber) > 0 {
		ret = n.appendRDNs(ret, []string{n.SerialNumber}, oidSerialNumber)
	}
	for _, atv := range n.ExtraNames {
		ret = append(ret, []AttributeTypeAndValue{atv})
	}

	mr := MyRDNSequence{
		Sequence: ret,
	}

	return mr
}

// String returns the string form of n, roughly following
// the RFC 2253 Distinguished Names syntax.
func (n Name) String() string {
	return n.ToRDNSequence().String()
}
