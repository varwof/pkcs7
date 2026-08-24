// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package pkcs7

import (
	"encoding/asn1"
	"fmt"
)

// AddCAdESTimestamp appends a CAdES signature timestamp (RFC 5126) to a PKCS#7 SignedData.
func AddCAdESTimestamp(pkcs7DER []byte, tstTokenDER []byte) ([]byte, error) {
	var ci ContentInfo
	if _, err := asn1.Unmarshal(pkcs7DER, &ci); err != nil {
		return nil, fmt.Errorf("unmarshal ContentInfo: %w", err)
	}
	var sd SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("unmarshal SignedData: %w", err)
	}

	for i := range sd.SignerInfos {
		tstAttr := asn1.RawValue{FullBytes: tstTokenDER}
		sd.SignerInfos[i].UnsignedAttributes = append(sd.SignerInfos[i].UnsignedAttributes, Attribute{
			Type:   OIDSignatureTimeStamp,
			Values: []asn1.RawValue{tstAttr},
		})
	}

	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("marshal SignedData: %w", err)
	}

	ci.Content.Bytes = sdDER
	ci.Content.FullBytes = nil
	return asn1.Marshal(ci)
}

// SignatureValue extracts the first signature value from a PKCS#7 SignedData.
func SignatureValue(pkcs7DER []byte) ([]byte, error) {
	var ci ContentInfo
	if _, err := asn1.Unmarshal(pkcs7DER, &ci); err != nil {
		return nil, fmt.Errorf("unmarshal ContentInfo: %w", err)
	}
	var sd SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("unmarshal SignedData: %w", err)
	}
	if len(sd.SignerInfos) == 0 {
		return nil, fmt.Errorf("no signer infos")
	}
	return sd.SignerInfos[0].Signature, nil
}

// HasCAdESUnsigned reports whether any SignerInfo has unsigned attributes.
func HasCAdESUnsigned(pkcs7DER []byte) bool {
	var ci ContentInfo
	if _, err := asn1.Unmarshal(pkcs7DER, &ci); err != nil {
		return false
	}
	var sd SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return false
	}
	for _, si := range sd.SignerInfos {
		if len(si.UnsignedAttributes) > 0 {
			return true
		}
	}
	return false
}
