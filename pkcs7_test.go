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
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

type testKeyPair struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

func newTestCertWithKey(t *testing.T, pub crypto.PublicKey, key crypto.Signer) *testKeyPair {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Signer",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testKeyPair{Cert: cert, Key: key}
}

func newECDSAP256(t *testing.T) *testKeyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newTestCertWithKey(t, &key.PublicKey, key)
}

func newECDSAP384(t *testing.T) *testKeyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newTestCertWithKey(t, &key.PublicKey, key)
}

func newECDSAP521(t *testing.T) *testKeyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newTestCertWithKey(t, &key.PublicKey, key)
}

func newRSA2048(t *testing.T) *testKeyPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return newTestCertWithKey(t, &key.PublicKey, key)
}

func newRSA4096(t *testing.T) *testKeyPair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	return newTestCertWithKey(t, &key.PublicKey, key)
}

func newEd25519(t *testing.T) *testKeyPair {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newTestCertWithKey(t, key.Public(), key)
}

func TestSelectHash(t *testing.T) {
	tests := []struct {
		name string
		k    *testKeyPair
		want crypto.Hash
	}{
		{"ECDSA P-256", newECDSAP256(t), crypto.SHA256},
		{"ECDSA P-384", newECDSAP384(t), crypto.SHA384},
		{"ECDSA P-521", newECDSAP521(t), crypto.SHA512},
		{"RSA 2048", newRSA2048(t), crypto.SHA256},
		{"RSA 4096", newRSA4096(t), crypto.SHA384},
		{"Ed25519", newEd25519(t), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectHash(tt.k.Cert)
			if got != tt.want {
				t.Errorf("selectHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignatureAlgorithmOID(t *testing.T) {
	tests := []struct {
		name string
		pub  crypto.PublicKey
		hash crypto.Hash
		want asn1.ObjectIdentifier
	}{
		{"ECDSA P-256 + SHA-256", &ecdsa.PublicKey{Curve: elliptic.P256()}, crypto.SHA256, OIDEcdsaWithSHA256},
		{"ECDSA P-256 + SHA-384", &ecdsa.PublicKey{Curve: elliptic.P256()}, crypto.SHA384, OIDEcdsaWithSHA256},
		{"ECDSA P-384 + SHA-256", &ecdsa.PublicKey{Curve: elliptic.P384()}, crypto.SHA256, OIDEcdsaWithSHA256},
		{"ECDSA P-384 + SHA-384", &ecdsa.PublicKey{Curve: elliptic.P384()}, crypto.SHA384, OIDEcdsaWithSHA384},
		{"ECDSA P-521 + SHA-256", &ecdsa.PublicKey{Curve: elliptic.P521()}, crypto.SHA256, OIDEcdsaWithSHA256},
		{"ECDSA P-521 + SHA-384", &ecdsa.PublicKey{Curve: elliptic.P521()}, crypto.SHA384, OIDEcdsaWithSHA384},
		{"ECDSA P-521 + SHA-512", &ecdsa.PublicKey{Curve: elliptic.P521()}, crypto.SHA512, OIDEcdsaWithSHA512},
		{"RSA + SHA-256", &rsa.PublicKey{N: big.NewInt(1), E: 65537}, crypto.SHA256, OIDRSAWithSHA256},
		{"RSA + SHA-384", &rsa.PublicKey{N: big.NewInt(1), E: 65537}, crypto.SHA384, OIDRSAWithSHA384},
		{"RSA + SHA-512", &rsa.PublicKey{N: big.NewInt(1), E: 65537}, crypto.SHA512, OIDRSAWithSHA512},
		{"Ed25519", ed25519.PublicKey{1}, 0, OIDEd25519},
		{"Ed25519 + SHA-256", ed25519.PublicKey{1}, crypto.SHA256, OIDEd25519},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := signatureAlgorithmOID(tt.pub, tt.hash)
			if !got.Equal(tt.want) {
				t.Errorf("signatureAlgorithmOID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHashOID(t *testing.T) {
	tests := []struct {
		name string
		h    crypto.Hash
		want asn1.ObjectIdentifier
	}{
		{"SHA-256", crypto.SHA256, OIDSHA256},
		{"SHA-384", crypto.SHA384, OIDSHA384},
		{"SHA-512", crypto.SHA512, OIDSHA512},
		{"default (0)", 0, OIDSHA256},
		{"MD5 fallback", crypto.MD5, OIDSHA256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hashOID(tt.h)
			if !got.Equal(tt.want) {
				t.Errorf("hashOID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func checkSignedData(t *testing.T, result []byte) *SignedData {
	t.Helper()
	if len(result) == 0 {
		t.Fatal("empty result")
	}
	var ci ContentInfo
	if _, err := asn1.Unmarshal(result, &ci); err != nil {
		t.Fatalf("unmarshal ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(OIDSignedData) {
		t.Fatalf("wrong content type: %v", ci.ContentType)
	}
	var sd SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("unmarshal SignedData: %v", err)
	}
	if sd.Version != 1 {
		t.Fatalf("expected version 1, got %d", sd.Version)
	}
	if len(sd.SignerInfos) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(sd.SignerInfos))
	}
	if len(sd.Certificates) == 0 {
		t.Fatal("no certificates")
	}
	return &sd
}

func TestBuildSignedDataDefault(t *testing.T) {
	kp := newECDSAP256(t)
	content := []byte("hello world")
	result, err := BuildSignedData(OIDData, content, kp.Cert, kp.Key, nil)
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}
	sd := checkSignedData(t, result)

	si := sd.SignerInfos[0]
	if !si.SignatureAlgorithm.Algorithm.Equal(OIDEcdsaWithSHA256) {
		t.Errorf("SignatureAlgorithm = %v, want ecdsa-with-SHA256", si.SignatureAlgorithm.Algorithm)
	}
	if !si.DigestAlgorithm.Algorithm.Equal(OIDSHA256) {
		t.Errorf("DigestAlgorithm = %v, want SHA-256", si.DigestAlgorithm.Algorithm)
	}
}

func TestBuildSignedDataWithChain(t *testing.T) {
	signer := newECDSAP256(t)
	ca := newECDSAP256(t)

	content := []byte("signed with chain")
	result, err := BuildSignedData(OIDData, content, signer.Cert, signer.Key, []*x509.Certificate{ca.Cert})
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}

	sd := checkSignedData(t, result)
	if len(sd.Certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(sd.Certificates))
	}
}

func TestBuildSignedDataEmptyContent(t *testing.T) {
	kp := newECDSAP256(t)
	_, err := BuildSignedData(OIDSignedData, nil, kp.Cert, kp.Key, nil)
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}
}

func TestBuildSignedDataWithHashP256SHA256(t *testing.T) {
	kp := newECDSAP256(t)
	content := []byte("test p256 sha256")
	result, err := BuildSignedDataWithHash(OIDData, content, kp.Cert, kp.Key, nil, crypto.SHA256)
	if err != nil {
		t.Fatalf("BuildSignedDataWithHash: %v", err)
	}
	sd := checkSignedData(t, result)
	si := sd.SignerInfos[0]
	if !si.SignatureAlgorithm.Algorithm.Equal(OIDEcdsaWithSHA256) {
		t.Errorf("SignatureAlgorithm = %v, want ecdsa-with-SHA256", si.SignatureAlgorithm.Algorithm)
	}
	if !si.DigestAlgorithm.Algorithm.Equal(OIDSHA256) {
		t.Errorf("DigestAlgorithm = %v, want SHA-256", si.DigestAlgorithm.Algorithm)
	}
}

func TestBuildSignedDataWithHashP384SHA384(t *testing.T) {
	kp := newECDSAP384(t)
	content := []byte("test p384 sha384")
	result, err := BuildSignedDataWithHash(OIDData, content, kp.Cert, kp.Key, nil, crypto.SHA384)
	if err != nil {
		t.Fatalf("BuildSignedDataWithHash: %v", err)
	}
	sd := checkSignedData(t, result)
	si := sd.SignerInfos[0]
	if !si.SignatureAlgorithm.Algorithm.Equal(OIDEcdsaWithSHA384) {
		t.Errorf("SignatureAlgorithm = %v, want ecdsa-with-SHA384", si.SignatureAlgorithm.Algorithm)
	}
	if !si.DigestAlgorithm.Algorithm.Equal(OIDSHA384) {
		t.Errorf("DigestAlgorithm = %v, want SHA-384", si.DigestAlgorithm.Algorithm)
	}
}

func TestBuildSignedDataWithHashRSA2048SHA256(t *testing.T) {
	kp := newRSA2048(t)
	content := []byte("test rsa 2048 sha256")
	result, err := BuildSignedDataWithHash(OIDData, content, kp.Cert, kp.Key, nil, crypto.SHA256)
	if err != nil {
		t.Fatalf("BuildSignedDataWithHash: %v", err)
	}
	sd := checkSignedData(t, result)
	si := sd.SignerInfos[0]
	if !si.SignatureAlgorithm.Algorithm.Equal(OIDRSAWithSHA256) {
		t.Errorf("SignatureAlgorithm = %v, want sha256WithRSAEncryption", si.SignatureAlgorithm.Algorithm)
	}
	if !si.DigestAlgorithm.Algorithm.Equal(OIDSHA256) {
		t.Errorf("DigestAlgorithm = %v, want SHA-256", si.DigestAlgorithm.Algorithm)
	}
}

func TestBuildSignedDataWithHashDetect(t *testing.T) {
	// hash=0 should auto-detect SHA-384 for P-384
	kp := newECDSAP384(t)
	content := []byte("test auto detect")
	result, err := BuildSignedDataWithHash(OIDData, content, kp.Cert, kp.Key, nil, 0)
	if err != nil {
		t.Fatalf("BuildSignedDataWithHash: %v", err)
	}
	sd := checkSignedData(t, result)
	si := sd.SignerInfos[0]
	if !si.SignatureAlgorithm.Algorithm.Equal(OIDEcdsaWithSHA384) {
		t.Errorf("SignatureAlgorithm = %v, want ecdsa-with-SHA384", si.SignatureAlgorithm.Algorithm)
	}
	if !si.DigestAlgorithm.Algorithm.Equal(OIDSHA384) {
		t.Errorf("DigestAlgorithm = %v, want SHA-384", si.DigestAlgorithm.Algorithm)
	}
}

// Benchmarks

func BenchmarkBuildSignedDataECDSA(b *testing.B) {
	kp := newBenchKey(b, elliptic.P256())
	data := make([]byte, 4096)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := BuildSignedDataWithHash(OIDData, data, kp.Cert, kp.Key, nil, crypto.SHA256)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildSignedDataRSA2048(b *testing.B) {
	kp := newBenchRSAKey(b, 2048)
	data := make([]byte, 4096)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := BuildSignedDataWithHash(OIDData, data, kp.Cert, kp.Key, nil, crypto.SHA256)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildSignedDataEd25519(b *testing.B) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	cert := newBenchCert(b, key)
	data := make([]byte, 4096)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := BuildSignedDataWithHash(OIDData, data, cert, key, nil, crypto.SHA512)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// -- AddCAdESTimestamp / HasCAdESUnsigned tests --

func TestHasCAdESUnsignedFalse(t *testing.T) {
	tp := newECDSAP256(t)
	content := []byte("no unsigned")
	der, err := BuildSignedData(OIDData, content, tp.Cert, tp.Key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if HasCAdESUnsigned(der) {
		t.Fatal("expected no unsigned attributes initially")
	}
}

func TestHasCAdESUnsignedBadInput(t *testing.T) {
	if HasCAdESUnsigned([]byte("garbage")) {
		t.Fatal("expected false for bad input")
	}
}

func TestAddCAdESTimestampBadInput(t *testing.T) {
	if _, err := AddCAdESTimestamp([]byte("not pkcs7"), []byte{0x05, 0x00}); err == nil {
		t.Fatal("expected error for bad PKCS#7 input")
	}
}

func TestSignatureValue(t *testing.T) {
	kp := newECDSAP256(t)
	content := []byte("test content")
	der, err := BuildSignedData(OIDData, content, kp.Cert, kp.Key, nil)
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}

	sig, err := SignatureValue(der)
	if err != nil {
		t.Fatalf("SignatureValue: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
}

func TestSignatureValueBadInput(t *testing.T) {
	_, err := SignatureValue([]byte("garbage"))
	if err == nil {
		t.Fatal("expected error for bad input")
	}

	_, err = SignatureValue([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	if err == nil {
		t.Fatal("expected error for malformed PKCS#7")
	}
}

func BenchmarkVerifyDetachedECDSA(b *testing.B) {
	b.Skip("VerifyDetached not implemented in pkcs7 package")
}

func BenchmarkVerifyDetachedRSA2048(b *testing.B) {
	b.Skip("VerifyDetached not implemented in pkcs7 package")
}

func newBenchKey(b *testing.B, curve elliptic.Curve) *testKeyPair {
	b.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	return &testKeyPair{Cert: newBenchCert(b, key), Key: key}
}

func newBenchRSAKey(b *testing.B, bits int) *testKeyPair {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		b.Fatal(err)
	}
	return &testKeyPair{Cert: newBenchCert(b, key), Key: key}
}

func newBenchCert(b *testing.B, key crypto.Signer) *x509.Certificate {
	b.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bench"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		b.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		b.Fatal(err)
	}
	return cert
}

// TestBuildSignedDataWithoutCertificates verifies RFC 3161 §2.4.1 certReq=false
// behavior: the SignedData.certificates field is empty while the signer can
// still be identified via the ESSCertID signing attribute.
func TestBuildSignedDataWithoutCertificates(t *testing.T) {
	kp := newECDSAP256(t)
	content := []byte("timestamp token content")

	result, err := BuildSignedDataWithoutCertificates(OIDSignedData, content, kp.Cert, kp.Key, nil)
	if err != nil {
		t.Fatalf("BuildSignedDataWithoutCertificates: %v", err)
	}

	var ci ContentInfo
	if _, err := asn1.Unmarshal(result, &ci); err != nil {
		t.Fatalf("unmarshal ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(OIDSignedData) {
		t.Fatalf("wrong content type: %v", ci.ContentType)
	}
	var sd SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("unmarshal SignedData: %v", err)
	}

	// RFC 3161 §2.4.1: certReq=false must yield an empty certificates field.
	if len(sd.Certificates) != 0 {
		t.Fatalf("expected empty certificates, got %d", len(sd.Certificates))
	}

	// The ESSCertID signing attribute (signingCertificateV2 → signingCertificate)
	// must still identify the signer.
	if len(sd.SignerInfos) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(sd.SignerInfos))
	}
	essCertID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	found := false
	for _, a := range sd.SignerInfos[0].SignedAttributes {
		if a.Type.Equal(essCertID) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected ESSCertID signing attribute present when certificates are omitted")
	}
}
