[![Build](https://github.com/falk-werner/openssl-example/actions/workflows/build.yml/badge.svg)](https://github.com/falk-werner/openssl-example/actions/workflows/build.yml)

# openssl-example

This repository contains examples to show how to use the OpenSSL C API.

## Build

```
cmake -B build
cmake --build build
./build/create_test_pki
```

## Examples

- [compute SHA256 checksumn](doc/sha256.md)
- [create a self-signed certficate](doc/self_signed.md)
- [create a certificate signing request (CSR)](doc/create_csr.md)
- [sign a CRS](doc/sign_csr.md)
- [create a certificate revokation list (CRL)](doc/create_crl.md)
- [verify a certificate](doc/verify_cert.md)
- [create a digital signature using cryptographic message syntax (CMS)](doc/cms_sign.md)
- [verify a CMS signature](doc/cms_verify.md)

_Note:_ Some of the examples make use of a [test PKI](doc/test_pki.md)

## Depedencies

- OpenSSL>3.0

