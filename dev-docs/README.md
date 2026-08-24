# pkcs7 开发文档

## 模块定位

纯 Go 零依赖 PKCS#7 / CMS SignedData 实现，服务于 gateway-core 审计签名和 Capability Register 规则签名。

## 文件结构

```
asn1.go   — ASN.1 类型定义 + BuildSignedData 系列 + CAdES 时间戳 + 工具函数
verify.go — 分离签名验证（VerifyDetached）
```

## 设计决策

### ASN.1 冻结策略

`asn1.go` 顶部声明 **ASN.1 FREEZE**：结构体类型和 OID 定义已冻结，只修 bug，不加新类型/新 OID。原因：

1. PKCS#7 ASN.1 类型一旦发布，下游（gateway-core、pki-pades、core）解析兼容性不可破
2. 新 CMS 属性（如 signingCertificateV2）需要 IETF RFC 支持，非本模块职责
3. 避免 ASN.1 编解码回归风险

### 签名算法自动选择

`selectHash(cert)` 根据公钥类型和参数自动选择哈希：

| 公钥类型 | 选择规则 |
|---------|---------|
| ECDSA P-256 | SHA-256 |
| ECDSA P-384 | SHA-384 |
| ECDSA P-521 | SHA-512 |
| RSA < 4096 bit | SHA-256 |
| RSA ≥ 4096 bit | SHA-384 |
| Ed25519 | 0（内部 SHA-512） |

### Ed25519 特殊处理

Ed25519 签名时 `crypto.SignerOpts` 传 `crypto.Hash(0)`，签的是原始 attrDER（Ed25519 内部做 SHA-512）。ECDSA/RSA 先哈希 attrDER 再签名。

### 签名属性构造

签名属性包含三个必选属性（RFC 5652 §11.2）：

1. **contentType**（1.2.840.113549.1.9.3）— 封装内容类型
2. **messageDigest**（1.2.840.113549.1.9.4）— eContent SHA-256 摘要
3. **signingCertificate**（1.2.840.113549.1.9.16.2.47）— ESS 签名证书属性（含 IssuerSerial + certHash）

签名属性 DER 的 SET 标签头在签名时跳过（规范要求 SignedAttributes 的 SET 标签不参与签名输入）。

### 验证流程（verify.go）

`VerifyDetached` 只验证签名本身，不验证证书链信任：

```
DER → ContentInfo → SignedData
  ├─ 按 serial 匹配签名证书
  ├─ 重算 content 哈希 ↔ messageDigest
  └─ verifySignature（RSA/ECDSA/Ed25519）
```

信任验证由调用方负责（`x509.Certificate.Verify` 或自定义信任库）。

## 依赖关系

```
github.com/varwof/pkcs7 (本模块)
  ↑
gateway-core (审计签名)
pki-pades      (PAdES 签名)
core           (签名验证)
```

零外部依赖，仅用 Go 标准库。

## 扩展约束

- 不添加新的 ASN.1 结构体类型
- 不添加新的 OID 常量
- 不添加在线验证（OCSP/CRL 由上层负责）
- 不添加 detached signature 解析（`BuildSignedDataWithDigest` 已支持 detached 构建）
