# openssl-example

This repository contains examples to show how to use the OpenSSL C API.

## Build and Run

```
cmake -B build
cmake --build build
```

## Examples

| Example | Description |
| ------- | ----------- |
| [self_signed](src/self_signed.cpp) | Create a self signed certificate. |
| [create_csr](src/create_csr.cpp) | Create a certificate signing request (CSR). |
| [sign_csr](src/sign_csr.cpp) | Sign a CSR. |
| [create_crl](src/create_crl.cpp) | Create certificate revokation list (CRL). |

### Create Self-Signed Certificate

```
> ./build/self_signed -k cert.key -f cert.pem
> openssl x509 -in cert.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC = org, DC = exampe, O = Example org, OU = Example Root CA, CN = Self Signed
        Validity
            Not Before: Nov 15 19:50:17 2023 GMT
            Not After : Nov 25 19:50:17 2023 GMT
        Subject: DC = org, DC = exampe, O = Example org, OU = Example Root CA, CN = Self Signed
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:d6:0e:b9:58:91:31:18:75:ac:9c:e5:10:e2:5b:
                    ...
                    c1:0f:77
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier: 
                F4:85:90:D3:B6:DA:76:30:AC:8B:2C:AA:0A:9F:49:0F:91:FC:0D:44
            X509v3 Authority Key Identifier: 
                F4:85:90:D3:B6:DA:76:30:AC:8B:2C:AA:0A:9F:49:0F:91:FC:0D:44
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        27:e3:a9:90:e6:3a:1e:06:e2:ed:c7:9d:dc:2f:a3:df:5c:81:
        ...
```

### Create Certificate Signing Request

```
> ./build/create_csr -k alice.key -f alice.csr
> openssl req -in alice.csr -text -noout
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: DC = org, DC = exampe, O = Example org, OU = Example CSR, CN = Req
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:88:02:4e:8a:f0:5c:6d:46:aa:21:d2:a7:23:34:
                    ...
                Exponent: 65537 (0x10001)
        Attributes:
            Requested Extensions:
                X509v3 Basic Constraints: critical
                    CA:TRUE
                X509v3 Key Usage: critical
                    Certificate Sign, CRL Sign
                X509v3 Subject Key Identifier: 
                    49:41:4E:44:F8:97:3F:ED:15:20:E7:67:76:0C:51:1F:C3:3C:ED:8B
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        37:1e:5d:77:96:0c:5d:4b:97:e5:a4:be:ee:65:e4:ee:17:1f:
        ...
```

### Sign CSR

Prerequisites:
- create a (self signed) certificate (`issuer.pem`) and private key (`issuer.key`)
- create a CSR (`subject.csr`)

```
> ./build/sign_csr -f subject.pem -c subject.csr -i issuer.pem -k issuer.key

> openssl x509 -in subject.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC = org, DC = exampe, O = Example org, OU = Example Root CA, CN = Self Signed
        Validity
            Not Before: Nov 15 21:00:40 2023 GMT
            Not After : Nov 25 21:00:40 2023 GMT
        Subject: DC = org, DC = exampe, O = Example org, OU = Example CSR, CN = Req
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:b4:e9:af:3a:3a:fa:46:f9:b2:90:3f:4a:72:69:
                    ...
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                41:CA:EE:B0:FA:5F:75:CC:6B:85:D0:F1:16:66:5C:C4:6F:50:74:62
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        46:62:90:d7:35:7d:ab:49:f6:09:ab:92:0c:9e:27:b7:18:28:
        ...

> openssl verify -CAfile issuer.pem subject.pem 
subject.pem: OK
```

### Create Certificate Revokation List

Prerequisites:
- create a (self signed) certificate (`issuer.pem`) and private key (`issuer.key`)
- create a CSR (`subject.csr`)
- sign CSR (`subject.pem`)

```
> ./build/create_crl -f subject.crl -c subject.pem -i issuer.pem -k issuer.key

> openssl crl -in subject.crl -text -noout
Certificate Revocation List (CRL):
        Version 2 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC = org, DC = exampe, O = Example org, OU = Example Root CA, CN = Self Signed
        Last Update: Nov 16 20:44:54 2023 GMT
        Next Update: Nov 26 20:44:54 2023 GMT
Revoked Certificates:
    Serial Number: 01
        Revocation Date: Nov 16 20:44:54 2023 GMT
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        dc:48:9f:16:9d:95:ee:95:5a:e1:b3:59:fa:ba:83:16:a3:d4:
        ...

> openssl verify -CAfile issuer.pem -CRLfile subject.crl -crl_check subject.pem
DC = org, DC = exampe, O = Example org, OU = Example CSR, CN = Req
error 23 at 0 depth lookup: certificate revoked
error subject.pem: verification failed
```

## Depedencies

- OpenSSL>3.0

