# Create Certificate Signing Request (CSR)

- Source: [create_csr.cpp](../src/create_csr.cpp)

## Create CSR using OpenSSL command line tool

```bash
openssl req -out donny.csr \
    -newkey rsa:4096 -keyout donny.key \
    -subj "/DC=org/DC=example/CN=Donny" \
    -days 356 \
    -noenc -batch
```

## View Contents of CSR

```bash
openssl req -in donny.csr -text -noout
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: DC = org, DC = example, CN = Donny
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:d8:8c:4c:b5:ae:46:b9:7a:82:26:3f:ca:10:b7:
                    ...
                Exponent: 65537 (0x10001)
        Attributes:
            (none)
            Requested Extensions:
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        8e:7c:4a:4e:8a:72:a1:5f:00:46:be:c7:c6:a2:63:2d:ed:5d:
        ...
```

## Create CSR using OpenSSL C API

To create a certificate signing request, the following steps can be performed:

1. Create a private key
2. Create a `X509_REQ` instance and initialize basic parameters
3. Set Subject
4. Set X509v3 Extensions
5. Sign CSR
6. Write CSR to PEM file

### 1. Create a private key

```C++
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cstdio>

// ...

EVP_PKEY * key = EVP_RSA_gen(4096);
FILE * file = fopen(keyfile.c_str(), "wb");
if (nullptr != file)
{
    PEM_write_PrivateKey(file, key, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(file);
}
```

A private key is needed to sign the certificate. It can be created using
`EVP_RSA_gen`. Note that a private key is actually a pair of keys: the
private and the public key.

The key can be written to a PEM file using `PEM_write_PrivateKey`. In the
example shown above, the key is sotred unencrypted. The function also
allows to encrypt the key with a password. Please refer to OpenSSL documentation
for further information.

### 2. Create a `X509_REQ` instance and initialize basic parameters

```C++
#include <openssl/x509.h>

//...

X509_REQ * req = X509_REQ_new();
X509_REQ_set_version(req, X509_REQ_VERSION_1);
X509_REQ_set_pubkey(req, key);
```

OpenSSL provides the `X509_REQ` struct to manage certificate signing requests.
A new request instance is created using `X509_REQ_new`. Basic initialization
contains setting the desired version and public key.

_(Note that `X509_REQ_VERSION_1` evaluates to 0.)_

### 3. Set Subject

```C++
void add_entry_by_NID(X509_NAME * name, int id, std::string const & value)
{
    X509_NAME_add_entry_by_NID(name, id, MBSTRING_UTF8, (unsigned char const *) value.c_str(), -1, -1, 0);
}

//...

X509_NAME * subject = X509_NAME_new();
add_entry_by_NID(subject, NID_domainComponent, "org");
add_entry_by_NID(subject, NID_domainComponent, "exampe");
add_entry_by_NID(subject, NID_organizationName, "Example org");
add_entry_by_NID(subject, NID_organizationalUnitName, "Example CSR");
add_entry_by_NID(subject, NID_commonName, common_name.c_str());
X509_REQ_set_subject_name(req, subject);
```

To describe the subject of the CSR, OpenSSL provides the `X509_NAME` struct.
There is a wide variety of values that can be set in a `X509_NAME` struct.
The most well known might be the so called `common name`. 
In HTTPS Server certificates the common name contains the DNS name of the server.

### 4. Set X509v3 Extensions

```C++
void add_extension(STACK_OF(X509_EXTENSION) * stack, X509_REQ * req, int id, char const * value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, nullptr, nullptr, req, nullptr, 0);
    X509_EXTENSION * extension = X509V3_EXT_conf_nid(nullptr, &ctx, id, value);
    sk_X509_EXTENSION_push(stack, extension);
}

//...

STACK_OF(X509_EXTENSION) * extensions = sk_X509_EXTENSION_new(nullptr);
add_extension(extensions, req, NID_basic_constraints, "critical,CA:TRUE");
add_extension(extensions, req, NID_key_usage, "critical,keyCertSign,cRLSign,digitalSignature");
add_extension(extensions, req, NID_subject_key_identifier, "hash");

X509_REQ_add_extensions(req, extensions);
sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
```

Certificate signing requests can also contain X509v3 extensions. One important extension
is `NID_key_usage`, which describes the purpose of the certificate generated from the
CSR.

### 5. Sign CSR

```C++
X509_REQ_sign(req, key, EVP_sha256());
```

Once every field of the CSR is set, it can be signed. For signing, the previously
generated private key is used. Certificate signing requests are always self-signed.

### 6. Write CSR to PEM file

```C++
file = fopen(filename.c_str(), "wb");
if (nullptr != file)
{
    PEM_write_X509_REQ(file, req);
    fclose(file);
}
```

Finally, the CRS can be stored to a PEM file using `PEM_write_X509_REQ`.

## Final remarks

Note that almost every field of a CSR an be alterted during the signing process.
Therefore, these fields should considered a proposal rather than mandatory
requirements.
