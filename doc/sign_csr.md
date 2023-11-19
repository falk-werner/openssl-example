# Sign CSR

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
