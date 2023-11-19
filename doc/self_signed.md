# Create Self-Signed Certificate

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
