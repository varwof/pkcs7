// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package pkcs7

import "encoding/asn1"

// Content type and signature algorithm OIDs (RFC 5652 / RFC 5754).
var (
	OIDSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDEcdsaWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDEcdsaWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDEcdsaWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	OIDRSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDRSAWithSHA384   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDRSAWithSHA512   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// OIDSignatureTimeStamp is the attribute type for CAdES signature timestamps (RFC 5126).
var OIDSignatureTimeStamp = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

// ASN.1 NULL raw value.
var nullRaw = asn1.RawValue{Class: 0, Tag: 5, Bytes: nil}
