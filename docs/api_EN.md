# pkcs7 API Reference

Pure standard-library PKCS#7 / CMS SignedData implementation. Zero external dependencies.

## Overview

```
BuildSignedData / BuildSignedDataWithHash / BuildSignedDataWithDigest
       ↓ DER
AddCAdESTimestamp → attach RFC 3161 timestamp
VerifyDetached → verify detached signature
SignatureValue / HasCAdESUnsigned → utility functions
```

## Signature Building

### BuildSignedData

```go
func BuildSignedData(
    eContentType asn1.ObjectIdentifier,
    eContent []byte,
    cert *x509.Certificate,
    signer crypto.Signer,
    chain []*x509.Certificate,
) ([]byte, error)
```

Builds PKCS#7 SignedData; the signature algorithm is selected automatically based on the certificate's public key (ECDSA/RSA/Ed25519).

- `eContentType` — encapsulated content type OID (e.g., `OIDSignedData`, `OIDData`)
- `eContent` — data to be signed; pass `nil` to produce a detached signature
- `cert` — signing certificate
- `signer` — corresponding private key
- `chain` — certificate chain (excluding `cert`)

### BuildSignedDataWithHash

```go
func BuildSignedDataWithHash(
    eContentType asn1.ObjectIdentifier,
    eContent []byte,
    cert *x509.Certificate,
    signer crypto.Signer,
    chain []*x509.Certificate,
    hash crypto.Hash,
) ([]byte, error)
```

Same as `BuildSignedData`, but with an explicit hash algorithm. When `hash=0`, selection is automatic.

### BuildSignedDataWithDigest

```go
func BuildSignedDataWithDigest(
    eContentType asn1.ObjectIdentifier,
    eContent, digest []byte,
    cert *x509.Certificate,
    signer crypto.Signer,
    chain []*x509.Certificate,
    hash crypto.Hash,
) ([]byte, error)
```

Builds SignedData using a precomputed digest. The `digest` is written directly into the messageDigest attribute without hashing `eContent`. Suitable for scenarios where the digest has already been computed externally.

- `eContent = nil` → detached signature (EncapContentInfo.Content omitted)

## CAdES Timestamp

### AddCAdESTimestamp

```go
func AddCAdESTimestamp(pkcs7DER []byte, tstTokenDER []byte) ([]byte, error)
```

Appends an RFC 3161 timestamp token (UnsignedAttribute `id-smime-aa-signatureTimeStampToken`) to an existing PKCS#7 DER. Added to all SignerInfos.

## Verification

### VerifyDetached

```go
func VerifyDetached(der []byte, content []byte) (*x509.Certificate, error)
```

Verifies a detached signature. Returns the signer's certificate.

Verification flow:
1. Parse ContentInfo → SignedData
2. Match the signing certificate by IssuerAndSerial
3. Recompute the content hash and compare against the messageDigest attribute
4. Verify the signature (RSA PKCS1v15 / ECDSA / Ed25519)

**Note**: does not verify certificate chain trust — only the signature itself. Callers must verify the returned certificate's chain trust themselves.

## Utility Functions

### SignatureValue

```go
func SignatureValue(pkcs7DER []byte) ([]byte, error)
```

Extracts the signature value of the first SignerInfo.

### HasCAdESUnsigned

```go
func HasCAdESUnsigned(pkcs7DER []byte) bool
```

Detects whether UnsignedAttributes are present (used to determine whether a timestamp has been attached).

## OID Constants

| Constant | Purpose |
|------|------|
| `OIDSignedData` | PKCS#7 SignedData contentType |
| `OIDData` | PKCS#7 data contentType |
| `OIDSHA256 / SHA384 / SHA512` | Digest algorithms |
| `OIDEcdsaWithSHA256/384/512` | ECDSA signature algorithms |
| `OIDRSAWithSHA256/384/512` | RSA signature algorithms |
| `OIDEd25519` | Ed25519 signature algorithm |
| `OIDSignatureTimeStamp` | CAdES timestamp attribute |

## ASN.1 Structs

The following types are exported ASN.1 encode/decode structs that are **frozen** — no feature extensions:

```go
type ContentInfo struct {
    ContentType asn1.ObjectIdentifier
    Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type SignedData struct {
    Version          int
    DigestAlgorithms []AlgorithmIdentifier
    EncapContentInfo EncapsulatedContentInfo
    Certificates     []asn1.RawValue  `asn1:"optional,implicit,tag:0"`
    SignerInfos      []SignerInfo
}

type SignerInfo struct {
    Version            int
    IssuerAndSerial    IssuerAndSerial
    DigestAlgorithm    AlgorithmIdentifier
    SignedAttributes   []Attribute `asn1:"optional,implicit,tag:0"`
    SignatureAlgorithm AlgorithmIdentifier
    Signature          []byte
    UnsignedAttributes []Attribute `asn1:"optional,implicit,tag:1"`
}
```

## Quick Example

```go
// Sign
der, err := pkcs7.BuildSignedData(
    pkcs7.OIDSignedData,
    payload,
    cert, signer, chain,
)

// Attach a timestamp
der, err = pkcs7.AddCAdESTimestamp(der, tstTokenDER)

// Verify the detached signature
signerCert, err := pkcs7.VerifyDetached(der, payload)
```
