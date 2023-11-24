# Sign CSR

- Source: [sign_csr.cpp](../src/sign_csr.cpp)

## Prerequisites

To sign a CSR, some prerequisites are needed:
- a CSR in PEM format
- a signing certificate in PEM format
- the private key of the signing certificate in PEM format

The prerequisites can be created using the [test PKI](test_pki.md).

## Sign CSR using OpenSSL command line tool

```bash
openssl x509 -req \
    -CA ./test-pki/signing_ca/signing_ca.pem \
    -CAkey ./test-pki/signing_ca/signing_ca.key \
    -in ./test-pki/donny/donny.csr \
    -out donny.pem
```

## View Certificate contents

```bash
openssl x509 -in donny.pem -text -noout
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number:
            45:ec:89:4d:39:25:19:ad:ab:49:86:e0:67:15:bd:f2:4a:5b:42:17
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC = org, DC = exampe, O = Example org, OU = CA Department, CN = Signing CA
        Validity
            Not Before: Nov 24 17:53:22 2023 GMT
            Not After : Dec 24 17:53:22 2023 GMT
        Subject: DC = org, DC = exampe, O = Example org, OU = CA Department, CN = donny
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:e3:11:f2:8e:d5:c6:d7:a9:60:16:cc:2b:9d:e6:
                    ...
                Exponent: 65537 (0x10001)
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        94:91:5a:78:eb:2f:e0:59:1f:e4:4a:f5:11:d1:a3:51:1a:ca:
        ...
```

## Sign CSR using OpenSSL C API

Signing a CSR is technically achived by creating a new X509 certificate.
The CSR is used to provide the public key and optionally other fields.

Note that in _real world applications_ each field that is taken from the CSR
should be checked with care. In doubt, the values of almost every field
are specified by the issuer of the certificate. In that sence, values
provided by the CSR can be seen as proposed rather than mandatory
requirements.

To sign a CRS and create an X509 certificate, the following steps
are needed:

1. Load CSR
2. Load issuer certificate and private key
3. Create X509 certificate and initialize basic values
4. Set subject
5. Set issuer
6. Set X509 extensions
7. Sign certificate
8. Write certificate to PEM file

### 1. Load CSR

```C++
#include <openssl/x509.h>
#include <openssl/pem.h>

// ...

X509_REQ * csr = nullptr;
file = fopen(csrfile.c_str(), "rb");
if (nullptr != file)
{
    PEM_read_X509_REQ(file, &csr, nullptr, nullptr);
    fclose(file);
}
```

OpenSSL provides the `X509_REQ` struct to manage certificate
signing requests. An existing CSR in PEM format can be loaded
using `PEM_read_X509_REQ`.

### 2. Load issuer certificate and private key


```C++
#include <openssl/evp.h>

// ...

EVP_PKEY * key = nullptr;
FILE * file = fopen(keyfile.c_str(), "rb");
if (nullptr != file)
{
    PEM_read_PrivateKey(file, &key, nullptr, nullptr);
    fclose(file);
}

X509 * issuer_cert = nullptr;
file = fopen(issuer.c_str(), "rb");
if (nullptr != file)
{
    PEM_read_X509(file, &issuer_cert, nullptr, nullptr);
    fclose(file);
}
```

OpenSSL provides the `EVP_PKEY` struct to manage private keys.
Note that a private key is actually a pair of private and public key.
An existing private key in PEM format ca be loaded using `PEM_read_PrivateKey`.
In real world applications, private keys might be encrypted. Please refer
to OpenSSL documentation for further information on that topic.

Likewise, OpenSSL provides the `X509` struct to manage X509 certificates.
An existing certificate can be loaded using `PEM_read_X509`.

### 3. Create X509 certificate and initialize basic values

```C++
X509 * cert = X509_new();
X509_set_version(cert, X509_VERSION_3);
ASN1_INTEGER_set(X509_get_serialNumber(cert), 1L);
X509_gmtime_adj(X509_get_notBefore(cert), 0L);
X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60L * 24L * 10L);    
X509_set_pubkey(cert, X509_REQ_get0_pubkey(csr));
```

Signing a CSR actually means to create a new X509 certificate based
on the data provided by the CSR. Therefore, a new `X509` instance
is created using `X509_new`. Some basic fields must be initialized:

- serial number  
  Each certificate has a serial number. The combination of issuer and
  serial number must be unique. The serial number is used in
  certificate revocation lists to identify the revoked certificate.
- not valid before  
  the date and time the certificate becomes valid
- not valid after  
  the date and time certificate becomes invalid
- public key  
  The public key is the only field that must be taken from the CSR.
  Any other field can be changed or omitted during signing.

### 4. Set subject

```C++
X509_set_subject_name(cert, X509_REQ_get_subject_name(csr));
```

The subject is typically taken from subject field of the CSR.
In real world applications, the subject should be checked with care.
Especially the `common name` should be validated.

### 5. Set issuer

```C++
X509_set_issuer_name(cert, X509_get_subject_name(issuer_cert));
```

The issuer of the newly created certificate is the subject of the
issuer certificate.

### 6. Set X509 extensions

```C++
STACK_OF(X509_EXTENSION) * extensions = X509_REQ_get_extensions(csr);
X509_EXTENSION * extension = sk_X509_EXTENSION_pop(extensions);
while (nullptr != extension)
{
    X509_add_ext(cert, extension, -1);
    X509_EXTENSION_free(extension);
    extension = sk_X509_EXTENSION_pop(extensions);
}
sk_X509_EXTENSION_free(extensions);
```

This example shows how to copy X509 extensions from the CSR to
the newly created certificate. In real world applications
any value from CSR should be checked with care before it is
copied to the newly created certificate. In doubt, the issuer
can freely change and / or omit these fields or a add
additional fields.

### 7. Sign certificate

```C++
X509_sign(cert, key, EVP_sha256());
```

Once every field of the newly created certificate is set, it
can be signed using the issuer's key.

### 8. Write certificate to PEM file

```C++
file = fopen(filename.c_str(), "wb");
if (file != nullptr)
{
    PEM_write_X509(file, cert);
    fclose(file);
}
```

Finally, the newly created certificate can be stored in a PEM
file using `PEM_write_X509`.
