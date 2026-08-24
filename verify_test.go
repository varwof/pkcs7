// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package pkcs7

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

func buildSignedDataForVerify(t *testing.T, key crypto.Signer, cert *x509.Certificate, content []byte, hash crypto.Hash) []byte {
	t.Helper()
	der, err := BuildSignedData(OIDData, content, cert, key, nil)
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}
	return der
}

func TestVerifyDetached_ECDSA(t *testing.T) {
	kp := newECDSAP256(t)
	content := []byte("hello verify")
	der := buildSignedDataForVerify(t, kp.Key, kp.Cert, content, 0)

	cert, err := VerifyDetached(der, content)
	if err != nil {
		t.Fatalf("VerifyDetached: %v", err)
	}
	if cert.SerialNumber.Cmp(kp.Cert.SerialNumber) != 0 {
		t.Errorf("wrong signer cert returned")
	}
}

func TestVerifyDetached_RSA(t *testing.T) {
	kp := newRSA2048(t)
	content := []byte("rsa verify test")
	der := buildSignedDataForVerify(t, kp.Key, kp.Cert, content, 0)

	cert, err := VerifyDetached(der, content)
	if err != nil {
		t.Fatalf("VerifyDetached: %v", err)
	}
	if cert.SerialNumber.Cmp(kp.Cert.SerialNumber) != 0 {
		t.Errorf("wrong signer cert returned")
	}
}

func TestVerifyDetached_Ed25519(t *testing.T) {
	kp := newEd25519(t)
	content := []byte("ed25519 verify test")
	der, err := BuildSignedDataWithHash(OIDData, content, kp.Cert, kp.Key, nil, crypto.SHA512)
	if err != nil {
		t.Fatalf("BuildSignedDataWithHash: %v", err)
	}

	cert, err := VerifyDetached(der, content)
	if err != nil {
		t.Fatalf("VerifyDetached: %v", err)
	}
	if cert.SerialNumber.Cmp(kp.Cert.SerialNumber) != 0 {
		t.Errorf("wrong signer cert returned")
	}
}

func TestVerifyDetached_WrongContent(t *testing.T) {
	kp := newECDSAP256(t)
	content := []byte("original content")
	der := buildSignedDataForVerify(t, kp.Key, kp.Cert, content, 0)

	wrongContent := []byte("tampered content")
	_, err := VerifyDetached(der, wrongContent)
	if err == nil {
		t.Fatal("expected error for wrong content")
	}
}

func TestVerifyDetached_InvalidDER(t *testing.T) {
	_, err := VerifyDetached([]byte("garbage"), []byte("content"))
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
}

func TestVerifyDetached_EmptySignerInfos(t *testing.T) {
	sd := SignedData{
		Version:          1,
		DigestAlgorithms: []AlgorithmIdentifier{{Algorithm: OIDSHA256, Parameters: nullRaw}},
		EncapContentInfo: EncapsulatedContentInfo{
			ContentType: OIDData,
			Content:     asn1.RawValue{Class: 0, Tag: asn1.TagOctetString, Bytes: []byte("x")},
		},
		SignerInfos: []SignerInfo{},
	}
	sdDER, _ := asn1.Marshal(sd)
	ci := ContentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sdDER},
	}
	ciDER, _ := asn1.Marshal(ci)

	_, err := VerifyDetached(ciDER, []byte("content"))
	if err == nil {
		t.Fatal("expected error for empty signer infos")
	}
}

func TestVerifyDetached_NoMatchingSigner(t *testing.T) {
	kp := newECDSAP256(t)
	content := []byte("test content")

	// Build signed data with a different cert that won't match the serial
	otherKP := newECDSAP256(t)
	der := buildSignedDataForVerify(t, kp.Key, kp.Cert, content, 0)

	var ci ContentInfo
	asn1.Unmarshal(der, &ci)
	var sd SignedData
	asn1.Unmarshal(ci.Content.Bytes, &sd)

	// Replace the embedded cert with a different one
	sd.Certificates = []asn1.RawValue{{FullBytes: otherKP.Cert.Raw}}
	sdDER, _ := asn1.Marshal(sd)
	ci.Content.Bytes = sdDER
	ci.Content.FullBytes = nil
	ciDER, _ := asn1.Marshal(ci)

	_, err := VerifyDetached(ciDER, content)
	if err == nil {
		t.Fatal("expected error for no matching signer")
	}
}

func TestHashFromOID_Supported(t *testing.T) {
	tests := []struct {
		oid  asn1.ObjectIdentifier
		want crypto.Hash
	}{
		{OIDSHA256, crypto.SHA256},
		{OIDSHA384, crypto.SHA384},
		{OIDSHA512, crypto.SHA512},
	}
	for _, tt := range tests {
		h, err := hashFromOID(tt.oid)
		if err != nil {
			t.Errorf("hashFromOID(%v) error: %v", tt.oid, err)
		}
		if h != tt.want {
			t.Errorf("hashFromOID(%v) = %v, want %v", tt.oid, h, tt.want)
		}
	}
}

func TestHashFromOID_Unsupported(t *testing.T) {
	_, err := hashFromOID(asn1.ObjectIdentifier{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for unsupported OID")
	}
}

func TestFindMessageDigest_Present(t *testing.T) {
	digest := []byte{1, 2, 3, 4}
	attrs := []Attribute{
		{
			Type:   asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4},
			Values: []asn1.RawValue{{Bytes: digest}},
		},
	}
	result := findMessageDigest(attrs)
	if result == nil || len(result) != 4 {
		t.Fatalf("expected digest, got %v", result)
	}
}

func TestFindMessageDigest_Missing(t *testing.T) {
	attrs := []Attribute{
		{
			Type:   asn1.ObjectIdentifier{1, 2, 3},
			Values: []asn1.RawValue{{Bytes: []byte{1}}},
		},
	}
	if findMessageDigest(attrs) != nil {
		t.Fatal("expected nil for missing messageDigest")
	}
}

func TestVerifySignature_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	digest := []byte("test digest for rsa")
	opts := crypto.SHA256
	h := crypto.SHA256.New()
	h.Write(digest)
	hashed := h.Sum(nil)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed)

	err := verifySignature(&key.PublicKey, hashed, sig, opts)
	if err != nil {
		t.Fatalf("RSA verifySignature should succeed: %v", err)
	}
}

func TestVerifySignature_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	digest := []byte("test digest for ecdsa")
	h := crypto.SHA256.New()
	h.Write(digest)
	hashed := h.Sum(nil)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, hashed)

	err := verifySignature(&key.PublicKey, hashed, sig, crypto.SHA256)
	if err != nil {
		t.Fatalf("ECDSA verifySignature should succeed: %v", err)
	}
}

func TestVerifySignature_Ed25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("test message for ed25519")
	sig := ed25519.Sign(priv, msg)

	err := verifySignature(pub, msg, sig, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Ed25519 verifySignature should succeed: %v", err)
	}
}

func TestVerifySignature_UnsupportedKeyType(t *testing.T) {
	err := verifySignature("not-a-key", []byte("digest"), []byte("sig"), crypto.SHA256)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestBuildSignedData_Ed25519(t *testing.T) {
	kp := newEd25519(t)
	content := []byte("ed25519 build test")
	result, err := BuildSignedDataWithHash(OIDData, content, kp.Cert, kp.Key, nil, crypto.SHA512)
	if err != nil {
		t.Fatalf("BuildSignedDataWithHash with Ed25519: %v", err)
	}
	sd := checkSignedData(t, result)
	si := sd.SignerInfos[0]
	if !si.SignatureAlgorithm.Algorithm.Equal(OIDEd25519) {
		t.Errorf("SignatureAlgorithm = %v, want Ed25519", si.SignatureAlgorithm.Algorithm)
	}
}

func TestBuildSignedDataWithDigest_Detached(t *testing.T) {
	kp := newECDSAP256(t)
	content := []byte("detached content")
	h := crypto.SHA256.New()
	h.Write(content)
	digest := h.Sum(nil)

	der, err := BuildSignedDataWithDigest(OIDData, nil, digest, kp.Cert, kp.Key, nil, crypto.SHA256)
	if err != nil {
		t.Fatalf("BuildSignedDataWithDigest: %v", err)
	}
	sd := checkSignedData(t, der)
	if sd.EncapContentInfo.Content.Bytes != nil {
		t.Error("expected nil content for detached signature")
	}
}
