# Verify signature using CMS

- Source: [cms_verify.cpp](../src/cms_verify.cpp)

## Prerequisites

In order verify a CMS signature the following artifacts are needed:

- the signature to check
- the data used to create the signature
- the certificate of the root CA
- any intermediate certificates not included in the CMS
- optionally any certificate recocation lists

The prerequisites can be created using the [test PKI](test_pki.md)
and the [cms_sign](cms_sign.md) example.

## Verification using OpenSSL command line tool

```bash
openssl cms -verify \
    -in data.sig -inform PEM -content data \
    -CAfile ./test-pki/root_ca/root_ca.pem

42
CMS Verification successful
```

## Verification using OpenSSL C API

In order to verify a digital signature using OpenSSL's C API, the
following steps are performed:

1. Load the signature
2. Provide a BIO for the data to check
3. Create a `X509_STORE` instance
4. Add trusted certifactes
5. Add certificate revocation lists
6. Perform the verification

### 1. Load the signature

```C++
#include <openssl/pem.h>
#include <openssl/cms.h>

// ...

CMS_ContentInfo * cms = nullptr;
FILE * file = fopen(signature_file.c_str(), "rb");
if (nullptr != file)
{
    PEM_read_CMS(file, &cms, nullptr, nullptr);
    fclose(file);
}
```

The signature is actually a CMS structure stored in a PEM file.
It can be loaded in a `CMS_ContentInfo` instance using `PEM_read_CMS`.

### 2. Provide a BIO for the data to check

```C++
#include <openssl/bio.h>

// ...

BIO * data = BIO_new_file(data_file.c_str(),"rb");
```

The data check must be provided by a `BIO`. Note that OpenSSL supports
a wide variety of different `BIO` types, including in-memory `BIO`s.

### 3. Create a `X509_STORE` instance

```C++
#include <openssl/x509.h>

// ...

X509_STORE * store = X509_STORE_new();
```

CMS verification is done using a `X509_STORE` instance. The store
contains trusted certificates and certificate revocation lists.

Note that certificate revocation list checking must be enabled
expicitly. Just adding CRLs to the store will not enable CRL
checking by default.

### 4. Add trusted certifactes

```C++
for(auto const & trusted_file: trusted_certfiles)
{
    X509 * trusted_cert = nullptr;
    file = fopen(trusted_file.c_str(), "rb");
    if (nullptr != file)
    {
        PEM_read_X509(file, &trusted_cert, nullptr, nullptr);
        fclose(file);
    }

    if (nullptr != trusted_cert)
    {
        X509_STORE_add_cert(store, trusted_cert);
        X509_free(trusted_cert);
    }
}
```

Trustes certificates are added to the store using `X509_STORE_add_cert`.

Note that these certificates are not validated. Real world applications
should make sure, these certificates are valid before adding them to
the store.

### 5. Add certificate revocation lists

```C++
if (!crl_files.empty())
{
    for(auto const & crl_file: crl_files)
    {
        X509_CRL * crl = nullptr;
        file = fopen(crl_file.c_str(), "rb");
        if (nullptr != file)
        {
            PEM_read_X509_CRL(file, &crl, nullptr, nullptr);
            fclose(file);
        }

        if (nullptr != crl)
        {
            X509_STORE_add_crl(store, crl);
            X509_CRL_free(crl);
        }
    }

    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL);
}
```

Certifcate revocation lists can be added to the store using `X509_STORE_add_crl`.

Note that just adding a CRL to the store will not enable CRL checking by default.
To enable CRL checking, the flag `X509_V_FLAG_CRL_CHECK_ALL` is set. This enables
checking CRLs for each untrusted certificate along the certificate chain. There
is also an option `X509_V_FLAG_CRL_CHECK` to enable checking the signer's
certificates only.

### 6. Perform the verification

```C++
int const result = CMS_verify(cms, nullptr, store, data, nullptr, CMS_DETACHED);
if (result == 1)
{

    std::cout << "OK" << std::endl;
}
else
{
    std::cout << "verifcation failed" << std::endl;
}
```

Once the store is set up, the verification can be performed using `CMS_verify`.

## Final thoughts

By default, `CMS_verify` will check the signature of each signer. When at least
one signer check fails, the verification fails. This is not always desired.
There are use cases, where at least one valid signer check is feasible, e.g.
when multiple signatures are used to implement certificate exchanges.

In this use cases, the flag `CMS_NO_SIGNER_CERT_VERIFY` can be used to skip
signer verification at all. Therefore, signer verification should be performed
separately. An example of this is given by [zipsign](https://github.com/falk-werner/zipsign/blob/main/lib/zipsign/verifier.cc).
