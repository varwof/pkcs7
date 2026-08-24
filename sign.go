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
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// SelectHash selects the signature hash algorithm based on the certificate's public key type.
func SelectHash(cert *x509.Certificate) crypto.Hash {
	return selectHash(cert)
}

func selectHash(cert *x509.Certificate) crypto.Hash {
	switch k := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return crypto.SHA256
		case elliptic.P384():
			return crypto.SHA384
		case elliptic.P521():
			return crypto.SHA512
		}
	case *rsa.PublicKey:
		if k.N.BitLen() >= 4096 {
			return crypto.SHA384
		}
		return crypto.SHA256
	case ed25519.PublicKey:
		return 0
	}
	return crypto.SHA256
}

func hashOID(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.SHA256:
		return OIDSHA256
	case crypto.SHA384:
		return OIDSHA384
	case crypto.SHA512:
		return OIDSHA512
	default:
		return OIDSHA256
	}
}

func signatureAlgorithmOID(pub crypto.PublicKey, hash crypto.Hash) asn1.ObjectIdentifier {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA384:
			if k.Curve == elliptic.P384() || k.Curve == elliptic.P521() {
				return OIDEcdsaWithSHA384
			}
			return OIDEcdsaWithSHA256
		case crypto.SHA512:
			return OIDEcdsaWithSHA512
		default:
			return OIDEcdsaWithSHA256
		}
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA384:
			return OIDRSAWithSHA384
		case crypto.SHA512:
			return OIDRSAWithSHA512
		default:
			return OIDRSAWithSHA256
		}
	case ed25519.PublicKey:
		return OIDEd25519
	}
	return OIDSHA256
}

// BuildSignedData builds a PKCS#7 SignedData with signing certificate attributes.
func BuildSignedData(eContentType asn1.ObjectIdentifier, eContent []byte, cert *x509.Certificate, signer crypto.Signer, chain []*x509.Certificate) ([]byte, error) {
	return BuildSignedDataWithHash(eContentType, eContent, cert, signer, chain, 0)
}

// BuildSignedDataWithHash builds a PKCS#7 SignedData using the specified hash algorithm.
func BuildSignedDataWithHash(eContentType asn1.ObjectIdentifier, eContent []byte, cert *x509.Certificate, signer crypto.Signer, chain []*x509.Certificate, hash crypto.Hash) ([]byte, error) {
	if hash == 0 {
		hash = selectHash(cert)
	}
	h := hash.New()
	h.Write(eContent)
	digest := h.Sum(nil)
	return BuildSignedDataWithDigest(eContentType, eContent, digest, cert, signer, chain, hash)
}

// BuildSignedDataWithDigest builds a PKCS#7 SignedData using a precomputed digest.
// Unlike BuildSignedDataWithHash which hashes eContent internally, this function
// uses the provided digest directly for the messageDigest attribute.
// If eContent is nil, the EncapContentInfo.Content is omitted (detached signature).
func BuildSignedDataWithDigest(eContentType asn1.ObjectIdentifier, eContent, digest []byte, cert *x509.Certificate, signer crypto.Signer, chain []*x509.Certificate, hash crypto.Hash) ([]byte, error) {
	if hash == 0 {
		hash = selectHash(cert)
	}

	contentTypeOID, _ := asn1.Marshal(eContentType)

	signingCertDER, err := buildSigningCertAttribute(cert)
	if err != nil {
		return nil, fmt.Errorf("build signingCertificate attribute: %w", err)
	}

	signedAttrs := []Attribute{
		{
			Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3},
			Values: []asn1.RawValue{
				{FullBytes: contentTypeOID},
			},
		},
		{
			Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4},
			Values: []asn1.RawValue{
				{Class: 0, Tag: asn1.TagOctetString, Bytes: digest},
			},
		},
		{
			Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47},
			Values: []asn1.RawValue{
				{FullBytes: signingCertDER},
			},
		},
	}

	wrapped, err := asn1.Marshal(struct {
		Attrs []Attribute `asn1:"set"`
	}{Attrs: signedAttrs})
	if err != nil {
		return nil, fmt.Errorf("marshal attributes: %w", err)
	}
	skip := 2
	if len(wrapped) > 1 && wrapped[1]&0x80 != 0 {
		skip = 2 + int(wrapped[1]&0x7f)
	}
	attrDER := wrapped[skip:]

	var sigInput []byte
	var signerOpts crypto.SignerOpts

	if _, ok := cert.PublicKey.(ed25519.PublicKey); ok {
		sigInput = attrDER
		signerOpts = crypto.Hash(0)
	} else {
		h2 := hash.New()
		h2.Write(attrDER)
		sigInput = h2.Sum(nil)
		signerOpts = hash
	}
	sig, err := signer.Sign(rand.Reader, sigInput, signerOpts)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	serialDER, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("marshal serial: %w", err)
	}

	allCerts := make([]asn1.RawValue, 0, 1+len(chain))
	allCerts = append(allCerts, asn1.RawValue{FullBytes: cert.Raw})
	for _, c := range chain {
		allCerts = append(allCerts, asn1.RawValue{FullBytes: c.Raw})
	}

	var eContentRaw asn1.RawValue
	if len(eContent) > 0 {
		wrapped, err := asn1.Marshal(asn1.RawValue{
			Class: 0, Tag: asn1.TagOctetString, Bytes: eContent,
		})
		if err != nil {
			return nil, fmt.Errorf("marshal eContent octets: %w", err)
		}
		eContentRaw = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: wrapped}
	}

	sigOID := signatureAlgorithmOID(cert.PublicKey, hash)
	digestOID := hashOID(hash)

	sd := SignedData{
		Version: 1,
		DigestAlgorithms: []AlgorithmIdentifier{
			{Algorithm: digestOID, Parameters: nullRaw},
		},
		EncapContentInfo: EncapsulatedContentInfo{
			ContentType: eContentType,
			Content:     eContentRaw,
		},
		Certificates: allCerts,
		SignerInfos: []SignerInfo{
			{
				Version: 1,
				IssuerAndSerial: IssuerAndSerial{
					Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
					SerialNumber: asn1.RawValue{FullBytes: serialDER},
				},
				DigestAlgorithm:    AlgorithmIdentifier{Algorithm: digestOID, Parameters: nullRaw},
				SignedAttributes:   signedAttrs,
				SignatureAlgorithm: AlgorithmIdentifier{Algorithm: sigOID, Parameters: nullRaw},
				Signature:          sig,
			},
		},
	}

	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("marshal SignedData: %w", err)
	}

	ci := ContentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sdDER},
	}

	return asn1.Marshal(ci)
}

func buildSigningCertAttribute(cert *x509.Certificate) ([]byte, error) {
	certHash := sha256.Sum256(cert.Raw)

	gn := asn1.RawValue{Class: 2, Tag: 4, IsCompound: true, Bytes: cert.RawIssuer}
	gnDER, err := asn1.Marshal(gn)
	if err != nil {
		return nil, err
	}
	gns := asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: gnDER}
	gnsDER, err := asn1.Marshal(gns)
	if err != nil {
		return nil, err
	}
	iss := struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}{
		Issuer:       asn1.RawValue{FullBytes: gnsDER},
		SerialNumber: cert.SerialNumber,
	}
	issDER, err := asn1.Marshal(iss)
	if err != nil {
		return nil, err
	}
	ess := struct {
		CertHash     []byte
		IssuerSerial asn1.RawValue `asn1:"optional"`
	}{
		CertHash:     certHash[:],
		IssuerSerial: asn1.RawValue{FullBytes: issDER},
	}
	essDER, err := asn1.Marshal(ess)
	if err != nil {
		return nil, err
	}
	sc := struct {
		Certs []asn1.RawValue
	}{
		Certs: []asn1.RawValue{{FullBytes: essDER}},
	}
	return asn1.Marshal(sc)
}
