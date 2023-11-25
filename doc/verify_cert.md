# Verify Certificate

# Verify signature using CMS

- Source [verify_cert.cpp](../src/verify_cert.cpp)

## Prerequisites

In order to verify a certfificate, the following prerequisites are needed:

- the certificate to verify
- the root CA's certificate
- any intermediate certificates to complete the certificate chain
- optionally certificate revocation lists to check 

The prerequisites can be created using the [test PKI](test_pki.md).

## Verify certificate using OpenSSL command line tool

### Verification without CRL checking

```bash
openssl verify -show_chain \
    -CAfile ./test-pki/root_ca/root_ca.pem \
    -untrusted ./test-pki/signing_ca/signing_ca.pem \
    ./test-pki/charlie/charlie.pem
 
./test-pki/charlie/charlie.pem: OK
Chain:
depth=0: DC = org, DC = exampe, O = Example org, OU = CA Department, CN = charlie (untrusted)
depth=1: DC = org, DC = exampe, O = Example org, OU = CA Department, CN = Signing CA (untrusted)
depth=2: DC = org, DC = exampe, O = Example org, OU = CA Department, CN = Root CA
```

Note that Charlies certificate got revoked. Since no CRL is provided and
CRL checking is inactive, the verification succeeds.

### Verification with CRL checking

```bash
openssl verify -show_chain \
    -CAfile ./test-pki/root_ca/root_ca.pem \
    -untrusted ./test-pki/signing_ca/signing_ca.pem \
    -crl_check_all -CRLfile ./test-pki/signing_ca/signing_ca.crl \
    ./test-pki/charlie/charlie.pem

DC = org, DC = exampe, O = Example org, OU = CA Department, CN = charlie
error 23 at 0 depth lookup: certificate revoked
error ./test-pki/charlie/charlie.pem: verification failed
```

Note that the option `-crl_check_all` must be provided to enable CRL
checking. Just specifiing a `-CRLfile` alone will not enable CRL checking.

## Verfy certficate using OpenSSL C API

To verify a certificate the following steps are perfomed:

1. Load the certificate to verify
2. Load a list of trusted certificates
3. Load a list of untrusted certificates
4. Load a list of certificate revokation lists
5. Create a verfifcation context
6. Perform verification

### 1. Load the certificate to verify

```C++
#include <openssl/x509.h>
#include <openssl/pem.h>

// ...

X509 * cert = nullptr;
FILE * file = fopen(certfile.c_str(), "rb");
if (nullptr != file)
{
    PEM_read_X509(file, &cert, nullptr, nullptr);
    fclose(file);
}
```

OpenSSL provided the `X509` struct to manage certificates.
An instance of `X509` can loaded from a PEM file using `PEM_read_X509`.

### 2. Load a list of trusted certificates

```C++
STACK_OF(X509) * load_certs(std::vector<std::string> files)
{
    STACK_OF(X509) * certs = sk_X509_new(nullptr);

    for(auto const & filename: files)
    {
        FILE * file = fopen(filename.c_str(), "rb");
        if (nullptr != file)
        {
            X509 * cert = nullptr;
            while (nullptr != PEM_read_X509(file, &cert, nullptr, nullptr))
            {
                sk_X509_push(certs, cert);
            } 

            fclose(file);
        }
    }

    return certs;
}

// ...

STACK_OF(X509) * trusted_certs = load_certs(trusted);
```

OpenSSL provides the `STACK_OF(X509)` struct to represent a list
of X509 certificates. Make sure, that only trusted certificates
are loaded such as the root CA's certificate, since no verification
of these certificates is performed.

### 3. Load a list of untrusted certificates

```C++
STACK_OF(X509) * untrusted_certs = load_certs(untrusted);
```

Untusted cerfificates are loaded the same way. Untrusted certificates
can be used to complete the certificate chain.

### 4. Load a list of certificate revokation lists

```C++
STACK_OF(X509_CRL) * load_crls(std::vector<std::string> files)
{
    STACK_OF(X509_CRL) * crls = sk_X509_CRL_new(nullptr);

    for(auto const & filename: files)
    {
        FILE * file = fopen(filename.c_str(), "rb");
        if (nullptr != file)
        {
            X509_CRL * crl = nullptr;
            PEM_read_X509_CRL(file, &crl, nullptr, nullptr);
            sk_X509_CRL_push(crls, crl);
            fclose(file);
        }
    }

    return crls;
}

// ...

STACK_OF(X509_CRL) * revoked = load_crls(crls);
```

OpenSSL provides the `STACK_OF(X509_CRL)` struct to represent
a list of certificate revokation lists.

### 5. Create a verfifcation context

```C++
X509_STORE_CTX * store = X509_STORE_CTX_new();
X509_STORE_CTX_init(store, nullptr, cert, nullptr);
X509_STORE_CTX_set0_trusted_stack(store, trusted_certs);
X509_STORE_CTX_set0_untrusted(store, untrusted_certs);

if (!crls.empty())
{
    X509_STORE_CTX_set0_crls(store, revoked);
    
    X509_VERIFY_PARAM * param = X509_VERIFY_PARAM_new();
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK_ALL);
    X509_STORE_CTX_set0_param(store, param);
}
```

OpenSSL provides the `X509_STORE_CTX` struct to perfom a
one shot certificate verification. Note that the context cannot
be re-used to verify multiple certificates. To do, each
certificate to check needs it's own verification context.

### 6. Perform verification

```C++
int const result = X509_verify_cert(store);
if (result == 1) 
{
    std::cout << "ok" << std::endl;
}
else
{
    int const code = X509_STORE_CTX_get_error(store);
    std::cout << "failed" << std::endl;
    std::cout << X509_verify_cert_error_string(code) << std::endl;
}
```

Once the verification context is set up, the verification can
be performed using `X509_verfiy_cert`. The verification results
are stored in context and can be obtained using
`X509_STORE_CTX_get_error`.
