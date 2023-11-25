# Create digitial signature using CMS

- Source: [cms_sign.cpp](../src/cms_sign.cpp)

## Prerequisites

In order to sign some data using CMS, some prerequisites are needed:

- certificate of the signer
- private key of the signer

The prerequisites can be created using the [test PKI](test_pki.md).

## Create digital signature using OpenSSL command line tool

```bash
echo 42 > data
openssl cms -sign -in data -outform pem \
    -signer ./test-pki/alice/alice.pem \
    -inkey ./test-pki/alice/alice.key  \
    -out data.sig
```

## Print CMS contents

```bash
openssl cms -cmsout -in data.sig -inform pem -print -noout

CMS_ContentInfo: 
  contentType: pkcs7-signedData (1.2.840.113549.1.7.2)
  d.signedData: 
    version: 1
    digestAlgorithms:
        algorithm: sha256 (2.16.840.1.101.3.4.2.1)
        parameter: <ABSENT>
    encapContentInfo: 
      eContentType: pkcs7-data (1.2.840.113549.1.7.1)
      eContent: <ABSENT>
    certificates:
      d.certificate: 
        cert_info: 
          version: 2
          serialNumber: 1
          signature: 
            algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
            parameter: NULL
          issuer: DC=org, DC=exampe, O=Example org, OU=CA Department, CN=Signing CA
          validity: 
            notBefore: Nov 25 12:33:27 2023 GMT
            notAfter: Dec  5 12:33:27 2023 GMT
          subject: DC=org, DC=exampe, O=Example org, OU=CA Department, CN=alice
          key:           X509_PUBKEY: 
            algor: 
              algorithm: rsaEncryption (1.2.840.113549.1.1.1)
              parameter: NULL
            public_key:  (0 unused bits)
              0000 - 30 82 02 0a 02 82 02 01-00 db 2a b7 95 54   0.........*..T
              ...
          issuerUID: <ABSENT>
          subjectUID: <ABSENT>
          extensions:
              object: X509v3 Basic Constraints (2.5.29.19)
              critical: TRUE
              value: 
                0000 - 30 03 01 01 ff                           0....

              object: X509v3 Key Usage (2.5.29.15)
              critical: TRUE
              value: 
                0000 - 03 02 01 86                              ....

              object: X509v3 Subject Key Identifier (2.5.29.14)
              critical: BOOL ABSENT
              value: 
                0000 - 04 14 5f f7 01 38 60 36-34 f7 6d ae 56   .._..8`64.m.V
                000d - 9c 88 b9 6a 0c 4c d9 83-44               ...j.L..D
        sig_alg: 
          algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
          parameter: NULL
        signature:  (0 unused bits)
          0000 - 86 ae 8c 5e ce b1 54 ee-f3 8f e7 0d d8 d1 53   ...^..T.......S
          ...
    crls:
      <ABSENT>
    signerInfos:
        version: 1
        d.issuerAndSerialNumber: 
          issuer: DC=org, DC=exampe, O=Example org, OU=CA Department, CN=Signing CA
          serialNumber: 1
        digestAlgorithm: 
          algorithm: sha256 (2.16.840.1.101.3.4.2.1)
          parameter: <ABSENT>
        signedAttrs:
            object: contentType (1.2.840.113549.1.9.3)
            set:
              OBJECT:pkcs7-data (1.2.840.113549.1.7.1)

            object: signingTime (1.2.840.113549.1.9.5)
            set:
              UTCTIME:Nov 25 14:47:11 2023 GMT

            object: messageDigest (1.2.840.113549.1.9.4)
            set:
              OCTET STRING:
                0000 - 9e 4c 59 bb 9e 5c a6 ca-84 0e b5 75 55   .LY..\.....uU
                ...

            object: S/MIME Capabilities (1.2.840.113549.1.9.15)
            set:
              SEQUENCE:
    0:d=0  hl=2 l= 106 cons: SEQUENCE          
    2:d=1  hl=2 l=  11 cons:  SEQUENCE          
    4:d=2  hl=2 l=   9 prim:   OBJECT            :aes-256-cbc
   15:d=1  hl=2 l=  11 cons:  SEQUENCE          
   17:d=2  hl=2 l=   9 prim:   OBJECT            :aes-192-cbc
   28:d=1  hl=2 l=  11 cons:  SEQUENCE          
   30:d=2  hl=2 l=   9 prim:   OBJECT            :aes-128-cbc
   41:d=1  hl=2 l=  10 cons:  SEQUENCE          
   43:d=2  hl=2 l=   8 prim:   OBJECT            :des-ede3-cbc
   53:d=1  hl=2 l=  14 cons:  SEQUENCE          
   55:d=2  hl=2 l=   8 prim:   OBJECT            :rc2-cbc
   65:d=2  hl=2 l=   2 prim:   INTEGER           :80
   69:d=1  hl=2 l=  13 cons:  SEQUENCE          
   71:d=2  hl=2 l=   8 prim:   OBJECT            :rc2-cbc
   81:d=2  hl=2 l=   1 prim:   INTEGER           :40
   84:d=1  hl=2 l=   7 cons:  SEQUENCE          
   86:d=2  hl=2 l=   5 prim:   OBJECT            :des-cbc
   93:d=1  hl=2 l=  13 cons:  SEQUENCE          
   95:d=2  hl=2 l=   8 prim:   OBJECT            :rc2-cbc
  105:d=2  hl=2 l=   1 prim:   INTEGER           :28
        signatureAlgorithm: 
          algorithm: rsaEncryption (1.2.840.113549.1.1.1)
          parameter: NULL
        signature: 
          0000 - a5 d9 d0 dd 1a 53 bc 47-f9 02 ae 74 0a a7 8b   .....S.G...t...
          ...
        unsignedAttrs:
          <ABSENT>
```

## Create digital signature using OpenSSL C API

In order to sign data with CMS using OpenSSL's C API, the
following steps are performed:

1. Create a `BIO` from the data to sign
2. Create an instance of `CMS_ContentInfo`
3. Add signers
4. Add additional certificates
4. Finalize CMS
5. Write CMS to PEM file

### 1. Create a `BIO` from the data to sign

```C++
#include <openssl/bio.h>

// ...

BIO * bio = BIO_new_file(filename.c_str(), "rb");
```

OpenSSL uses the `BIO` struct as abstraction for I/O operations.
To create the signature, a `BIO` for the data to sign is needed. To
create a `BIO` from a file `BIO_new_file` is used.

Note that there is a variety of different `BIO` types, including
in-memory `BIO`s.

### 2. Create an instance of `CMS_ContentInfo`

```C++
#include <openssl/cms.h>

// ...

int flags = CMS_DETACHED ;
CMS_ContentInfo * info = CMS_sign(nullptr, nullptr, nullptr, bio, flags | CMS_PARTIAL);
```

OpenSSL provides the `CMS_ContentInfo` struct to build and sign
a CMS. A new instance of this struct is created using `CMS_sign`.

Note that the way this is used here, there is actually no signing
done in this step. `CMS_sign` can be used as one-shot operation,
but since we want to add additional signers and certificates,
Partial creation is choosen here by setting the `CMS_PARTIAL`
flag.

Also note the flag `CMS_DETACHED` which excludes the data from
the CMS.

### 3. Add signers

```C++
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

for(size_t i = 0; i < signers.size(); i++)
{
    X509 * additional_signer = nullptr;
    file = fopen(signers[i].c_str(), "rb");
    if (nullptr != file)
    {
        PEM_read_X509(file, &additional_signer, nullptr, nullptr);
        fclose(file);
    }
    if (nullptr == additional_signer)
    {
        std::cout << "error: warning: failed to load additional signer \'" << signers[i] << "\': skip" << std::endl; 
        continue;
    }

    EVP_PKEY * additional_key = nullptr;
    file = fopen(signer_keys[i].c_str(), "rb");
    if (nullptr != file)
    {
        PEM_read_PrivateKey(file, &additional_key, nullptr, nullptr);
        fclose(file);
    }
    if (nullptr == additional_key)
    {
        std::cout << "error: warning: failed to load additional key \'" << signer_keys[i] << "\': skip" << std::endl;
        X509_free(additional_signer);
        continue;
    }

    CMS_add1_signer(info, additional_signer, additional_key, nullptr, flags | CMS_PARTIAL);

    EVP_PKEY_free(additional_key);
    X509_free(additional_signer);
}
```

A CMS needs at least one signer, but multiple signers are allowed.
A signer is added via `CMS_add1_signer` once it's certificate and
private key are loaded.

Note that during verification each signer is checked. The verification
will fail if any signature is invalid, revoked or it's chain cannot be
built.

### 4. Add additional certificates

```C++
for(auto const & cerfile: additional_certs)
{
    X509 * additional_cert = nullptr;
    FILE * file = fopen(cerfile.c_str(), "rb");
    if (nullptr != file)
    {
        PEM_read_X509(file, &additional_cert, nullptr, nullptr);
        fclose(file);
    }
    if (nullptr != additional_cert)
    {
        CMS_add0_cert(info, additional_cert);
    }
}
```

CMS allows to include additional certificates. There certificates
are treated as _untrusted_ during verification an can be used to
complete the certificate chain.

### 4. Finalize CMS

```C++
CMS_final(info, bio, nullptr, flags);
```

Once all signers and additional certificates are added to the CMS,
it can be finalized using `CMS_final`.

Note that certificate revocation lists can also be added to a CMS.
Although this is not covered by this example.

### 5. Write CMS to PEM file

```C++
FILE file = fopen((filename + ".sig").c_str(), "wb");
if (nullptr != file)
{
    PEM_write_CMS(file, info);
    fclose(file);
}
```

Finally the CMS can be written to a PEM file using `PEM_write_CMS`.
