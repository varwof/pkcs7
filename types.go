// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// WARNING: ASN.1 FREEZE: This package's ASN.1 structures are frozen.
// Bug fixes only — no new ASN.1 struct types, no new OIDs.
// See dev-docs/ASN1_DISCIPLINE.md.

package pkcs7

import "encoding/asn1"

// ContentInfo is the CMS SignedData content information wrapper (RFC 5652 §5.2).
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// AlgorithmIdentifier is the signature/digest algorithm identifier (RFC 5652 §10.1).
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// SignedData is the CMS SignedData structure (RFC 5652 §5.1).
type SignedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"optional,implicit,tag:0"`
	SignerInfos      []SignerInfo    `asn1:"set"`
}

// EncapsulatedContentInfo is the signed content encapsulated within SignedData (RFC 5652 §5.2).
type EncapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional"`
}

// SignerInfo is the information for a single signer (RFC 5652 §5.3).
type SignerInfo struct {
	Version            int
	IssuerAndSerial    IssuerAndSerial
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttributes   []Attribute `asn1:"optional,implicit,tag:0"`
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
	UnsignedAttributes []Attribute `asn1:"optional,implicit,tag:1"`
}

// Attribute is the CMS attribute structure (RFC 5652 §5.3).
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// IssuerAndSerial identifies the signer certificate by issuer and serial number (RFC 5652 §5.3).
type IssuerAndSerial struct {
	Issuer       asn1.RawValue `asn1:"set"`
	SerialNumber asn1.RawValue
}
