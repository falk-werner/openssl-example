# Create Certificate Revokation List

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
