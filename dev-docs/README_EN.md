# pkcs7 Developer Documentation

## Module Positioning

Pure Go, zero-dependency PKCS#7 / CMS SignedData implementation, serving gateway-core audit signing and Capability Register rule signing.

## File Structure

```
asn1.go   — ASN.1 type definitions + BuildSignedData family + CAdES timestamp + utility functions
verify.go — Detached signature verification (VerifyDetached)
```

## Design Decisions

### ASN.1 Freeze Policy

The top of `asn1.go` declares an **ASN.1 FREEZE**: struct types and OID definitions are frozen — bug fixes only, no new types/OIDs. Reasons:

1. Once the PKCS#7 ASN.1 types are published, downstream parsing compatibility (gateway-core, pki-pades, core) must not be broken
2. New CMS attributes (e.g., signingCertificateV2) require IETF RFC support and are not this module's responsibility
3. Avoids ASN.1 encode/decode regression risk

### Automatic Signature Algorithm Selection

`selectHash(cert)` automatically selects the hash based on public key type and parameters:

| Public Key Type | Selection Rule |
|---------|---------|
| ECDSA P-256 | SHA-256 |
| ECDSA P-384 | SHA-384 |
| ECDSA P-521 | SHA-512 |
| RSA < 4096 bit | SHA-256 |
| RSA ≥ 4096 bit | SHA-384 |
| Ed25519 | 0 (SHA-512 internal) |

### Ed25519 Special Handling

When signing with Ed25519, `crypto.SignerOpts` passes `crypto.Hash(0)` and the raw attrDER is signed (Ed25519 does SHA-512 internally). ECDSA/RSA hash the attrDER first, then sign.

### Signed Attributes Construction

The signed attributes include three mandatory attributes (RFC 5652 §11.2):

1. **contentType** (1.2.840.113549.1.9.3) — encapsulated content type
2. **messageDigest** (1.2.840.113549.1.9.4) — SHA-256 digest of eContent
3. **signingCertificate** (1.2.840.113549.1.9.16.2.47) — ESS signing certificate attribute (with IssuerSerial + certHash)

The SET tag header of the signed-attributes DER is skipped during signing (the spec requires that the SET tag of SignedAttributes not participate in the signature input).

### Verification Flow (verify.go)

`VerifyDetached` verifies only the signature itself, not certificate chain trust:

```
DER → ContentInfo → SignedData
  ├─ match the signing certificate by serial
  ├─ recompute content hash ↔ messageDigest
  └─ verifySignature (RSA/ECDSA/Ed25519)
```

Trust verification is the caller's responsibility (`x509.Certificate.Verify` or a custom trust store).

## Dependency Relationships

```
github.com/varwof/pkcs7 (this module)
  ↑
gateway-core (audit signing)
pki-pades      (PAdES signing)
core           (signature verification)
```

Zero external dependencies; uses only the Go standard library.

## Extension Constraints

- Do not add new ASN.1 struct types
- Do not add new OID constants
- Do not add online verification (OCSP/CRL are handled by upper layers)
- Do not add detached signature parsing (`BuildSignedDataWithDigest` already supports detached construction)
