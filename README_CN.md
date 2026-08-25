# varwof-pkcs7

> 纯 Go PKCS#7 / CMS SignedData 签名与验证库，零外部依赖

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/pkcs7)](https://pkg.go.dev/github.com/varwof/pkcs7)

[English](README.md)

## 什么是 varwof-pkcs7？

纯标准库 PKCS#7 / CMS SignedData 签名/验证实现。零外部依赖，支持 ECDSA/RSA/Ed25519 签名、CAdES-T 时间戳附加、分离签名验证。被 varwof-core 用于 CA 证书链签名和代码签名。

## 快速开始

```go
import "github.com/varwof/pkcs7"

// 签名
der, err := pkcs7.BuildSignedData(
    pkcs7.OIDData, data, cert, signer, nil,
)

// 验证
signerCert, err := pkcs7.VerifyDetached(der, data)

// 附加 CAdES-T 时间戳
tsDER, _ := requestTimestamp(der)
signed, _ := pkcs7.AddCAdESTimestamp(der, tsDER)
```

## 安装

```bash
go get github.com/varwof/pkcs7@v0.1.0
```

## 特性

- 零外部依赖，纯标准库
- PKCS#7 SignedData 签名
- CAdES-T 时间戳附加
- 分离签名验证
- 支持 ECDSA (P-256/P-384/P-521) / RSA / Ed25519
- 自动根据证书公钥选择签名算法

## 生态位置

pkcs7 提供 CMS 签名原语，被 core 的代码签名和 CA 证书链签名使用。本项目是 [Open Invention Network](https://openinventionnetwork.com/) 成员。

## 链接

| | |
|---|---|
| 主页 | https://varwof.com |
| 社区 | https://varwof.org |
| IETF 草案 | [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) |
| 许可证 | Apache-2.0 |
| 成员 | [Open Invention Network](https://openinventionnetwork.com/) |
