# pkcs7 API 参考

纯标准库 PKCS#7 / CMS SignedData 实现。零外部依赖。

## 概览

```
BuildSignedData / BuildSignedDataWithHash / BuildSignedDataWithDigest
       ↓ DER
AddCAdESTimestamp → 附加 RFC 3161 时间戳
VerifyDetached → 验证分离签名
SignatureValue / HasCAdESUnsigned → 工具函数
```

## 签名构建

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

构建 PKCS#7 SignedData，签名算法自动根据证书公钥选择（ECDSA/RSA/Ed25519）。

- `eContentType` — 封装内容类型 OID（如 `OIDSignedData`、`OIDData`）
- `eContent` — 待签名数据，传 `nil` 生成分离签名
- `cert` — 签名证书
- `signer` — 对应私钥
- `chain` — 证书链（不含 `cert`）

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

同 `BuildSignedData`，但显式指定哈希算法。`hash=0` 时自动选择。

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

使用预计算摘要构建 SignedData。`digest` 直接写入 messageDigest 属性，不再对 `eContent` 哈希。适用于外部已计算摘要的场景。

- `eContent = nil` → 分离签名（EncapContentInfo.Content 省略）

## CAdES 时间戳

### AddCAdESTimestamp

```go
func AddCAdESTimestamp(pkcs7DER []byte, tstTokenDER []byte) ([]byte, error)
```

向已有 PKCS#7 DER 追加 RFC 3161 时间戳令牌（UnsignedAttribute `id-smime-aa-signatureTimeStampToken`）。所有 SignerInfo 均添加。

## 验证

### VerifyDetached

```go
func VerifyDetached(der []byte, content []byte) (*x509.Certificate, error)
```

验证分离签名。返回签名者证书。

验证流程：
1. 解析 ContentInfo → SignedData
2. 按 IssuerAndSerial 匹配签名证书
3. 重新计算 content 哈希，比对 messageDigest 属性
4. 验证签名（RSA PKCS1v15 / ECDSA / Ed25519）

**注意**：不验证证书链信任关系，仅验证签名本身。调用方需自行验证返回证书的链信任。

## 工具函数

### SignatureValue

```go
func SignatureValue(pkcs7DER []byte) ([]byte, error)
```

提取第一个 SignerInfo 的签名值。

### HasCAdESUnsigned

```go
func HasCAdESUnsigned(pkcs7DER []byte) bool
```

检测是否存在 UnsignedAttributes（用于判断是否已附加时间戳）。

## OID 常量

| 常量 | 用途 |
|------|------|
| `OIDSignedData` | PKCS#7 SignedData contentType |
| `OIDData` | PKCS#7 data contentType |
| `OIDSHA256 / SHA384 / SHA512` | 摘要算法 |
| `OIDEcdsaWithSHA256/384/512` | ECDSA 签名算法 |
| `OIDRSAWithSHA256/384/512` | RSA 签名算法 |
| `OIDEd25519` | Ed25519 签名算法 |
| `OIDSignatureTimeStamp` | CAdES 时间戳属性 |

## ASN.1 结构体

以下类型均为导出 ASN.1 编解码结构体，**已冻结**，不做功能扩展：

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

## 快速示例

```go
// 签名
der, err := pkcs7.BuildSignedData(
    pkcs7.OIDSignedData,
    payload,
    cert, signer, chain,
)

// 附加时间戳
der, err = pkcs7.AddCAdESTimestamp(der, tstTokenDER)

// 验证分离签名
signerCert, err := pkcs7.VerifyDetached(der, payload)
```
