# Varwof PKCS#7

Pure standard-library PKCS#7 / CMS SignedData signing/verification implementation. Zero external dependencies.

## Features

- Zero external dependencies, pure standard library
- PKCS#7 SignedData signing (BuildSignedData / BuildSignedDataWithHash / BuildSignedDataWithDigest)
- CAdES-T timestamp attachment (AddCAdESTimestamp)
- Detached signature verification (VerifyDetached)
- Supports ECDSA (P-256/P-384/P-521) / RSA / Ed25519
- Automatic hash algorithm selection based on certificate public key

## Install

```bash
go get github.com/varwof/pkcs7@v0.1.0
```

## Usage

```go
import "github.com/varwof/pkcs7"

// Sign
der, err := pkcs7.BuildSignedData(
    pkcs7.OIDData,    // content type
    data,             // data to sign
    cert,             // signing certificate
    signer,           // signing private key
    nil,              // certificate chain (optional)
)

// Verify
signerCert, err := pkcs7.VerifyDetached(der, data)

// Attach CAdES-T timestamp
tsDER, _ := requestTimestamp(der)
signed, _ := pkcs7.AddCAdESTimestamp(der, tsDER)
```

## License

Apache-2.0
