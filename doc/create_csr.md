# Create Certificate Signing Request

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
