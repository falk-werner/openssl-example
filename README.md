[![Build](https://github.com/falk-werner/openssl-example/actions/workflows/build.yml/badge.svg)](https://github.com/falk-werner/openssl-example/actions/workflows/build.yml)

# openssl-example

This repository contains examples to show how to use the OpenSSL C API.

## Build

```
cmake -B build
cmake --build build
./build/create_test_pki
```

## Glossary

| Abbreviation | Description |
| ------------ | ----------- |
| [X.509](https://en.wikipedia.org/wiki/X.509) |  A standard defining the format of public key certificates |
| [CA](https://en.wikipedia.org/wiki/Certificate_authority) | **C**ertificate **A**uthority |
| [CSR](https://en.wikipedia.org/wiki/Certificate_signing_request) | **C**ertificate **S**igning **R**equest |
| [CRL](https://en.wikipedia.org/wiki/Certificate_revocation_list) | **C**ertififcate **R**evocation **L**ist |
| [CMS](https://en.wikipedia.org/wiki/Cryptographic_Message_Syntax) | **C**ryptographic **M**essage **S**yntax |
| [PKI](https://en.wikipedia.org/wiki/Public_key_infrastructure) | **P**ublic **K**ey **I**nfrastructure |

## Examples

- [compute SHA256 checksumn](doc/sha256.md)
- [create a self-signed certficate](doc/self_signed.md)
- [create a certificate signing request (CSR)](doc/create_csr.md)
- [sign a CRS](doc/sign_csr.md)
- [create a certificate revokation list (CRL)](doc/create_crl.md)
- [verify a certificate](doc/verify_cert.md)
- [create a digital signature using cryptographic message syntax (CMS)](doc/cms_sign.md)
- [verify a CMS signature](doc/cms_verify.md)

### Remarks

- Some of the examples make use of a [test PKI](doc/test_pki.md).
- The purpose of this repository is to give an overview about OpenSSL's C API.
  Therefore, there is almost no error handling contained in the examples.

## Depedencies

- [OpenSSL](https://www.openssl.org/)>3.0

