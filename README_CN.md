# Varwof PKCS#7

> ⚠️ **预览版** — 不可用于生产环境。独立实现的 PKCS#7/CMS，尚未经过独立
> 安全审计；依赖前请用自有测试向量验证。

纯标准库 PKCS#7 / CMS SignedData 签名/验证实现，零外部依赖。

## 特性

- 零外部依赖，纯标准库
- PKCS#7 SignedData 签名（BuildSignedData / BuildSignedDataWithHash / BuildSignedDataWithDigest）
- CAdES-T 时间戳附加（AddCAdESTimestamp）
- 分离签名验证（VerifyDetached）
- 支持 ECDSA (P-256/P-384/P-521) / RSA / Ed25519
- 自动根据证书公钥选择签名算法

## 安装

```bash
go get github.com/varwof/pkcs7@v0.1.0
```

## 使用

```go
import "github.com/varwof/pkcs7"

// 签名
der, err := pkcs7.BuildSignedData(
    pkcs7.OIDData,    // 签名内容类型
    data,             // 待签名数据
    cert,             // 签名证书
    signer,           // 签名私钥
    nil,              // 证书链（可选）
)

// 验证
signerCert, err := pkcs7.VerifyDetached(der, data)

// 附加 CAdES-T 时间戳
tsDER, _ := requestTimestamp(der)
signed, _ := pkcs7.AddCAdESTimestamp(der, tsDER)
```

## 许可证

Apache-2.0
