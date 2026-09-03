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
	"strings"
	"testing"
	"time"
)

// newAttackerCert builds a self-signed certificate with the given subject and
// serial so tests can simulate a certificate that shares identity attributes
// with a legitimate signer but is under attacker control.
func newAttackerCert(t *testing.T, cn string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// swapEmbeddedCert re-marshals a SignedData ContentInfo after replacing the
// certificates carrier with a single attacker-provided certificate.
func swapEmbeddedCert(t *testing.T, der []byte, attackCert *x509.Certificate) []byte {
	t.Helper()
	var ci ContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatal(err)
	}
	var sd SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatal(err)
	}
	sd.Certificates = []asn1.RawValue{{FullBytes: attackCert.Raw}}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	ci.Content.Bytes = sdDER
	ci.Content.FullBytes = nil
	ciDER, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}
	return ciDER
}

// TestVerifyDetached_RejectsSameSerialDifferentIssuer guards against a serial
// collision attack: a certificate sharing only the serial number (globally not
// unique) with the legitimate signer must not be accepted as the signer. Signer
// identity is bound by issuer AND serial.
func TestVerifyDetached_RejectsSameSerialDifferentIssuer(t *testing.T) {
	victim := newECDSAP256(t)
	content := []byte("attestation data")
	der := buildSignedDataForVerify(t, victim.Key, victim.Cert, content, 0)

	// Attacker cert with the SAME serial (1) but a different issuer.
	attackCert := newAttackerCert(t, "attacker.example", 1)

	tampered := swapEmbeddedCert(t, der, attackCert)
	_, err := VerifyDetached(tampered, content)
	if err == nil {
		t.Fatal("expected rejection: cert with same serial but different issuer must not be trusted")
	}
	if !strings.Contains(err.Error(), "no matching signer") {
		t.Fatalf("expected errNoSigner, got: %v", err)
	}
}

// TestVerifyDetached_RejectsSwappedKeyWithSameIdentity guards against identity
// mis-attribution: a certificate with the SAME issuer AND serial (and hence the
// same IssuerAndSerial selector) but a DIFFERENT public key must be rejected via
// the signingCertificate (ESSCertID) digest binding.
func TestVerifyDetached_RejectsSwappedKeyWithSameIdentity(t *testing.T) {
	victim := newECDSAP256(t)
	content := []byte("attestation data")
	der := buildSignedDataForVerify(t, victim.Key, victim.Cert, content, 0)

	// A different key with the identical issuer ("Test Signer") and serial (1).
	attacker := newECDSAP256(t)
	attackCert := attacker.Cert

	tampered := swapEmbeddedCert(t, der, attackCert)
	_, err := VerifyDetached(tampered, content)
	if err == nil {
		t.Fatal("expected rejection: cert with same issuer+serial but different key must not be trusted")
	}
	if !strings.Contains(err.Error(), "signingCertificate attribute does not match") {
		t.Fatalf("expected ESSCertID binding rejection, got: %v", err)
	}
}

// TestVerifyDetached_BuildRoundTrip ensures legitimately built tokens still
// verify after the hardened signer-identity matching.
func TestVerifyDetached_BuildRoundTrip(t *testing.T) {
	for _, kp := range []struct {
		name  string
		build func(t *testing.T) *testKeyPair
	}{
		{"ecdsa", newECDSAP256},
		{"rsa", newRSA2048},
	} {
		t.Run(kp.name, func(t *testing.T) {
			pair := kp.build(t)
			content := []byte("round trip")
			der := buildSignedDataForVerify(t, pair.Key, pair.Cert, content, 0)
			cert, err := VerifyDetached(der, content)
			if err != nil {
				t.Fatalf("VerifyDetached: %v", err)
			}
			if cert.SerialNumber.Cmp(pair.Cert.SerialNumber) != 0 {
				t.Fatal("wrong signer cert returned")
			}
		})
	}
}
