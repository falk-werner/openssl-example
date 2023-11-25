# Create Certificate Revocation List (CRL)

- Source: [create_crl.cpp](src/create_crl.cpp)

## Prerequisites

To create a certificate revocation list some prerequisites are needed:
- the certificate to revoke
- the certificate of the issuer of the certificate to revoke
- the private key of the issuer
- when using OpenSSL command line tool, a ca configuration file is needed _(see below)_

The prerequisites can be created using the [test PKI](test_pki.md).

## Create CRL using OpenSSL command line tool

```bash 
openssl ca -gencrl \
    -config ./test-pki/signing_ca/ca.conf \
    -cert ./test-pki/signing_ca/signing_ca.pem \
    -keyfile ./test-pki/signing_ca/signing_ca.key \
    -revoke ./test-pki/alice/alice.pem \
    -out alice.crl -batch
```

To revoke a certificate using OpenSSL, a CA configuration file is
needed. An example is given below. The test PKI also contains one.

```ini
[ ca ]
default_ca      = CA_default            # The default ca section
 
[ CA_default ]

dir            = ./test-pki/signing_ca # top dir
database       = $dir/index.txt        # index file.
new_certs_dir  = $dir/newcerts         # new certs dir

certificate    = $dir/signing.pem      # The CA cert
serial         = $dir/serial           # serial no file
private_key    = $dir/signing.key      # CA private key
RANDFILE       = $dir/signing.rand     # random number file

default_days   = 365                   # how long to certify for
default_crl_days= 30                   # how long before next CRL
default_md     = sha256                # md to use

policy         = policy_any            # default policy
email_in_dn    = no                    # Don't add the email into cert DN

name_opt       = ca_default            # Subject name display option
cert_opt       = ca_default            # Certificate display option
copy_extensions = none                 # Don't copy extensions from request

[ policy_any ]
countryName            = supplied
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional
```

## View CRL contents

```bash
openssl crl -in alice.crl -text -noout
Certificate Revocation List (CRL):
        Version 1 (0x0)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC = org, DC = exampe, O = Example org, OU = CA Department, CN = Signing CA
        Last Update: Nov 25 13:03:21 2023 GMT
        Next Update: Dec 25 13:03:21 2023 GMT
Revoked Certificates:
    Serial Number: 01
        Revocation Date: Nov 25 12:33:57 2023 GMT
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        99:e4:01:96:45:1f:c3:51:05:b7:73:ff:b4:cf:d8:c4:98:b5:
        ...
```

## Create CRL using OpenSSL C API

To revoke a given certificate, the following steps are performed:

1. Load certificate to revoke
2. Load issuer key and certificate
3. Create and initialize CRL
4. Add certificate to revoke
5. Sort and sign CRL
6. Write CRL to PEM file

### 1. Load certificate to revoke

```C++
#include <openssl/x509.h>
#include <openssl/pem.h>

// ...

X509 * cert = nullptr;
file = fopen(certfile.c_str(), "rb");
if (nullptr != file)
{
    PEM_read_X509(file, &cert, nullptr, nullptr);
    fclose(file);
}
```

The certificate to revoke can be loaded in a `X509` struct instance
using `PEM_read_X509`.

### 2. Load issuer key and certificate

```C++
#include <openssl/evp.h>

// ...

EVP_PKEY * key = nullptr;
file = fopen(keyfile.c_str(), "rb");
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

OpenSSL provided the `EVP_PKEY` struct to manage private keys.
To load a private key from a PEM file, `PEM_read_PrivateKey` is used.
Note that real world private keys might be encrypted. Please refer to
OpenSSL documentation for further information on this topic. Also note
that a private key is actually a pair of private and public key.

Likewise, OpenSSL provides the `X509` struct to manage certificates.
The issuer certificate is loaded from a PEM file using `PEM_read_X509`.

### 3. Create and initialize CRL

```C++
X509_CRL * crl = X509_CRL_new();

X509_CRL_set_version(crl, X509_CRL_VERSION_2);
X509_CRL_set_issuer_name(crl, X509_get_subject_name(issuer_cert));

ASN1_TIME * lastUpdate = ASN1_TIME_new();
X509_gmtime_adj(lastUpdate, 0);
X509_CRL_set_lastUpdate(crl, lastUpdate);
ASN1_TIME_free(lastUpdate);

ASN1_TIME * nextUpdate = ASN1_TIME_new();
X509_gmtime_adj(nextUpdate, 60 * 60 * 24 * 10);
X509_CRL_set_nextUpdate(crl, nextUpdate);
ASN1_TIME_free(nextUpdate);
```

OpenSSL provided the `X509_CRL` struct to manage certicate
revokation lists. A new instance can be created using
`X509_CRL_new`. A real world application might load an
existing CRL using `PEM_read_X509_CRL` and add the newly
revoked certificate.

To use the CRL, some basic field should be initialized:

- version  
  speicifies the version of the CRL _(note that `X509_CRL_VERSION_2` evaluated to 1):
- issuer of the CRL  
  equals to the subject of the issuer certificate
- date and time of last update
- date and time of the next sheduled update 

### 4. Add certificate to revoke

```C++
X509_REVOKED * revoked = X509_REVOKED_new();
ASN1_TIME * revoked_at = ASN1_TIME_new();
X509_gmtime_adj(revoked_at, 0);
X509_REVOKED_set_revocationDate(revoked, revoked_at);
ASN1_TIME_free(revoked_at);

X509_REVOKED_set_serialNumber(revoked, X509_get_serialNumber(cert));
X509_CRL_add0_revoked(crl, revoked);
```

The certificate to revoke is identfied by it's serial number in
the CRL. Therefore each certficate needs a unique serial number.

### 5. Sort and sign CRL

```C++
X509_CRL_sort(crl);
X509_CRL_sign(crl, key, EVP_sha256());
```

Once the CRL is created or updated, it can be sorted and signed by
the issuer key.

### 6. Write CRL to PEM file

```C++
file = fopen(filename.c_str(), "wb");
if (nullptr != file)
{
    PEM_write_X509_CRL(file, crl);
    fclose(file);
}
```

Finally, the CRL can be written to a PEM file using `PEM_write_X509_CRL`.
