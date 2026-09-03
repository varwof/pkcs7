// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

var errNoSigner = errors.New("no matching signer certificate found in PKCS#7")

func VerifyDetached(der []byte, content []byte) (*x509.Certificate, error) {
	var ci ContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("unmarshal ContentInfo: %w", err)
	}
	var sd SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("unmarshal SignedData: %w", err)
	}
	if len(sd.SignerInfos) == 0 {
		return nil, errors.New("no signer infos in PKCS#7")
	}
	si := sd.SignerInfos[0]

	serial := parseSerial(si.IssuerAndSerial.SerialNumber)

	var signerCert *x509.Certificate
	for _, cr := range sd.Certificates {
		cert, err := x509.ParseCertificate(cr.FullBytes)
		if err != nil {
			continue
		}
		// Security: identify the signer by issuer AND serial, never by serial
		// alone. Serial numbers are not globally unique, so a cert sharing only a
		// serial number must not be able to claim another signer's identity.
		if certificateMatches(si.IssuerAndSerial, cert, serial) {
			signerCert = cert
			break
		}
	}
	if signerCert == nil {
		return nil, errNoSigner
	}

	// Security: when the signed attributes carry a signingCertificate (ESSCertID)
	// attribute, it binds the signature to a specific certificate by digest. Verify
	// it matches the certificate that actually holds the signing key, so a token
	// embedding a certificate with the same issuer+serial but a different public key
	// is rejected rather than mis-attributed.
	if err := verifySigningCertAttr(si.SignedAttributes, signerCert); err != nil {
		return nil, err
	}

	hash, err := hashFromOID(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("digest algorithm: %w", err)
	}

	recomputed := hash.New()
	recomputed.Write(content)
	computedDigest := recomputed.Sum(nil)

	messageDigest := findMessageDigest(si.SignedAttributes)
	if messageDigest == nil {
		return nil, errors.New("no messageDigest attribute found")
	}
	if !bytes.Equal(messageDigest, computedDigest) {
		return nil, fmt.Errorf("content digest mismatch: got %x, expected %x", computedDigest, messageDigest)
	}

	wrapped, err := asn1.Marshal(struct {
		Attrs []Attribute `asn1:"set"`
	}{Attrs: si.SignedAttributes})
	if err != nil {
		return nil, fmt.Errorf("marshal signed attributes: %w", err)
	}
	skip := 2
	if len(wrapped) > 1 && wrapped[1]&0x80 != 0 {
		skip = 2 + int(wrapped[1]&0x7f)
	}
	attrDER := wrapped[skip:]

	var sigInput []byte
	var opts crypto.SignerOpts
	if _, ok := signerCert.PublicKey.(ed25519.PublicKey); ok {
		sigInput = attrDER
		opts = crypto.Hash(0)
	} else {
		h := hash.New()
		h.Write(attrDER)
		sigInput = h.Sum(nil)
		opts = hash
	}

	if err := verifySignature(signerCert.PublicKey, sigInput, si.Signature, opts); err != nil {
		return nil, fmt.Errorf("signature verification: %w", err)
	}

	return signerCert, nil
}

func hashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(OIDSHA256):
		return crypto.SHA256, nil
	case oid.Equal(OIDSHA384):
		return crypto.SHA384, nil
	case oid.Equal(OIDSHA512):
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash OID: %v", oid)
	}
}

func findMessageDigest(attrs []Attribute) []byte {
	for _, a := range attrs {
		if a.Type.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}) {
			if len(a.Values) > 0 {
				return a.Values[0].Bytes
			}
		}
	}
	return nil
}

func verifySignature(pub crypto.PublicKey, digest []byte, sig []byte, opts crypto.SignerOpts) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		hash, ok := opts.(crypto.Hash)
		if !ok || hash == 0 {
			return errors.New("invalid hash for RSA verification")
		}
		return rsa.VerifyPKCS1v15(k, hash, digest, sig)
	case *ecdsa.PublicKey:
		var ecdsaSig struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(sig, &ecdsaSig); err != nil {
			return fmt.Errorf("unmarshal ECDSA signature: %w", err)
		}
		if !ecdsa.Verify(k, digest, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil
	case ed25519.PublicKey:
		if ed25519.Verify(k, digest, sig) {
			return nil
		}
		return errors.New("Ed25519 signature verification failed")
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// oidSigningCertV2 is the signingCertificateV2 attribute (RFC 5035 §3) that the
// builder emits as an ESSCertID carrying the SHA-256 digest of the signer cert.
var oidSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

func parseSerial(rv asn1.RawValue) *big.Int {
	serial := new(big.Int)
	if err := serial.UnmarshalText(rv.Bytes); err != nil {
		serial.SetBytes(rv.Bytes)
	}
	return serial
}

// certificateMatches reports whether cert is the signer named by IssuerAndSerial:
// both the serial number and the issuer distinguished name must match.
func certificateMatches(ias IssuerAndSerial, cert *x509.Certificate, serial *big.Int) bool {
	if cert.SerialNumber.Cmp(serial) != 0 {
		return false
	}
	issuerDER := ias.Issuer.FullBytes
	if len(issuerDER) == 0 {
		issuerDER = ias.Issuer.Bytes
	}
	return bytes.Equal(cert.RawIssuer, issuerDER)
}

// essCertIDv2 mirrors RFC 5035 §3: hashAlgorithm defaults to id-sha256 in our
// builder, followed by the certificate digest.
type essCertIDv2 struct {
	HashAlgorithm AlgorithmIdentifier `asn1:"optional"`
	CertHash      []byte
}

type signingCertV2 struct {
	Certs []essCertIDv2
}

// verifySigningCertAttr checks, when a signingCertificate (ESSCertID) attribute
// is present in the signed attributes, that one of its certificate digests equals
// the digest of cert. Returns nil if the attribute is absent (older/other
// producers); fails closed if present but none of the digests match.
func verifySigningCertAttr(attrs []Attribute, cert *x509.Certificate) error {
	hasAttr := false
	for _, a := range attrs {
		if !a.Type.Equal(oidSigningCertV2) {
			continue
		}
		hasAttr = true
		for _, v := range a.Values {
			var sc signingCertV2
			if _, err := asn1.Unmarshal(v.FullBytes, &sc); err != nil {
				continue
			}
			for _, e := range sc.Certs {
				hash := crypto.SHA256 // RFC 5035 default
				if len(e.HashAlgorithm.Algorithm) > 0 {
					h, err := hashFromOID(e.HashAlgorithm.Algorithm)
					if err != nil {
						return fmt.Errorf("signingCertificate hash algorithm: %w", err)
					}
					hash = h
				}
				sum := hash.New()
				sum.Write(cert.Raw)
				if bytes.Equal(sum.Sum(nil), e.CertHash) {
					return nil
				}
			}
		}
	}
	if !hasAttr {
		return nil
	}
	return errors.New("signingCertificate attribute does not match signer certificate")
}
