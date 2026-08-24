// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package pkcs7

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func selfSignCert(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func buildTestSignedDataDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSignCert(t, key)
	content := []byte("test content")
	der, err := BuildSignedData(OIDData, content, cert, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestAddCAdESTimestamp_Valid(t *testing.T) {
	sdDER := buildTestSignedDataDER(t)
	tstToken := []byte{0x30, 0x03, 0x02, 0x01, 0x00}

	result, err := AddCAdESTimestamp(sdDER, tstToken)
	if err != nil {
		t.Fatalf("AddCAdESTimestamp: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("empty result")
	}
	if !HasCAdESUnsigned(result) {
		t.Fatal("expected unsigned attributes after adding timestamp")
	}

	var ci ContentInfo
	if _, err := asn1.Unmarshal(result, &ci); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	var sd SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("unmarshal SignedData: %v", err)
	}
	if len(sd.SignerInfos) == 0 {
		t.Fatal("no signer infos")
	}
	si := sd.SignerInfos[0]
	if len(si.UnsignedAttributes) == 0 {
		t.Fatal("expected unsigned attributes")
	}
	found := false
	for _, attr := range si.UnsignedAttributes {
		if attr.Type.Equal(OIDSignatureTimeStamp) {
			found = true
		}
	}
	if !found {
		t.Fatal("expected SignatureTimeStamp attribute")
	}
}

func TestAddCAdESTimestamp_InvalidDER(t *testing.T) {
	_, err := AddCAdESTimestamp([]byte("garbage"), []byte{0x05, 0x00})
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

func TestAddCAdESTimestamp_ValidContentInfo_BadSignedData(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSignCert(t, key)

	// Build a valid ContentInfo but with garbage SignedData bytes
	ci := ContentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{0xDE, 0xAD}},
	}
	ciDER, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}
	_ = cert
	_, err = AddCAdESTimestamp(ciDER, []byte{0x05, 0x00})
	if err == nil {
		t.Fatal("expected error for bad SignedData inside valid ContentInfo")
	}
}

func TestSignatureValue_Valid(t *testing.T) {
	sdDER := buildTestSignedDataDER(t)
	sig, err := SignatureValue(sdDER)
	if err != nil {
		t.Fatalf("SignatureValue: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature value")
	}
}

func TestSignatureValue_InvalidDER(t *testing.T) {
	_, err := SignatureValue([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

func TestSignatureValue_NoSigners(t *testing.T) {
	sd := SignedData{
		Version:          1,
		DigestAlgorithms: []AlgorithmIdentifier{{Algorithm: OIDSHA256, Parameters: nullRaw}},
		EncapContentInfo: EncapsulatedContentInfo{
			ContentType: OIDData,
			Content:     asn1.RawValue{Class: 0, Tag: asn1.TagOctetString, Bytes: []byte("x")},
		},
		SignerInfos: []SignerInfo{},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	ci := ContentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sdDER},
	}
	ciDER, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}

	_, err = SignatureValue(ciDER)
	if err == nil {
		t.Fatal("expected error for no signer infos")
	}
}

func TestHasCAdESUnsigned_True(t *testing.T) {
	sdDER := buildTestSignedDataDER(t)
	tstToken := []byte{0x30, 0x03, 0x02, 0x01, 0x00}
	result, err := AddCAdESTimestamp(sdDER, tstToken)
	if err != nil {
		t.Fatal(err)
	}
	if !HasCAdESUnsigned(result) {
		t.Fatal("expected true after AddCAdESTimestamp")
	}
}

func TestHasCAdESUnsigned_False(t *testing.T) {
	sdDER := buildTestSignedDataDER(t)
	if HasCAdESUnsigned(sdDER) {
		t.Fatal("expected false for plain signed data")
	}
}

func TestHasCAdESTimestampRoundTrip(t *testing.T) {
	sdDER := buildTestSignedDataDER(t)
	tstToken := []byte{0x30, 0x03, 0x02, 0x01, 0x00}

	result, err := AddCAdESTimestamp(sdDER, tstToken)
	if err != nil {
		t.Fatal(err)
	}

	sig1, err := SignatureValue(sdDER)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := SignatureValue(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig1) != len(sig2) {
		t.Fatalf("signature length changed: %d vs %d", len(sig1), len(sig2))
	}
}
