# Create Self-Signed Certificate

- Source: [self_signed.cpp](../src/self_signed.cpp)

## Create self-signed certificate using OpenSSL command line tool

```bash
openssl req -x509 -out cert.pem \
    -newkey rsa:4096 -keyout key.pem \
    -days 356 \
    -subj "/DC=org/DC=example/CN=Self Signed" \
    -noenc -batch
```

The `openssl req` command is typically used to create certificate
signing requesrs (CSR), but it can also be used to create self
signed certificates.

## View contents of certificate

```bash
openssl x509 -in cert.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            23:00:2e:b5:ce:a2:fb:e9:35:09:91:0c:68:f0:f6:6d:7d:c3:ae:ba
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC = org, DC = example, CN = Self Signed
        Validity
            Not Before: Nov 23 19:32:05 2023 GMT
            Not After : Nov 13 19:32:05 2024 GMT
        Subject: DC = org, DC = example, CN = Self Signed
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:bf:ae:0a:89:d9:3b:18:5f:14:81:aa:f1:21:9a:
                    ...
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                1F:CD:7A:6B:4A:96:FA:15:9F:10:23:E4:75:20:08:28:3B:D7:FA:55
            X509v3 Authority Key Identifier: 
                1F:CD:7A:6B:4A:96:FA:15:9F:10:23:E4:75:20:08:28:3B:D7:FA:55
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        3b:e9:0d:6c:0b:f8:eb:fc:7c:d1:41:34:ed:84:a3:e6:9f:94:
        ...
```

## Create self-signed certificate using OpenSSL C API

To create a self signed certificate via OpenSSL's C API, the
following steps are needed:

1. Create a private key
2. Create a certificate and set basic properties
3. Set subject and issuer
4. Add X509v3 extenstions
5. Sign the certificate
6. Write the certificate to PEM file

### 1. Create private key

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

### 2. Create a certificate and set basic properties

```C++
#include <openssl/x509.h>

//...

X509 * cert = X509_new();
X509_set_version(cert, X509_VERSION_3);
ASN1_INTEGER_set(X509_get_serialNumber(cert), 1L);
X509_gmtime_adj(X509_get_notBefore(cert), 0L);
X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60L * 24L * days_valid);
X509_set_pubkey(cert, key);
```

OpenSSL proviced the `X509` struct to manage X509 certifcates. After
creation, some basic properties should be set:

- the X509 version to be used  
  _(note that `X509_VERSION_3` is actual the numeric value 2)_
- the serial number  
- the date and time when the certificate becomes valid
- the date and time when the certificate expires
- the public key  
  (note that `X509_set_pubkey` use the public key part of the previously created private key)

### 3. Set subject and issuer

```C++
void add_entry_by_NID(X509_NAME * name, int id, std::string const & value)
{
    X509_NAME_add_entry_by_NID(name, id, MBSTRING_UTF8, (unsigned char const *) value.c_str(), -1, -1, 0);
}

// ...

X509_NAME * subject = X509_NAME_new();
add_entry_by_NID(subject, NID_domainComponent, "org");
add_entry_by_NID(subject, NID_domainComponent, "exampe");
add_entry_by_NID(subject, NID_organizationName, "Example org");
add_entry_by_NID(subject, NID_organizationalUnitName, "Example Root CA");
add_entry_by_NID(subject, NID_commonName, "Self-Signed");
X509_set_subject_name(cert, subject);
X509_set_issuer_name(cert, subject);
```

Every certificate needs a subject and an issues. While the subject describes
the certificate itself, the issuer describes who signs the certificate. In
case of self-signed certificates both values are the same.

OpenSSL provides the `X509_NAME` struct to describes subjects and issuers. There
is a wide variety of values that can be set in a `X509_NAME` struct. The most
well known might be the so called `common name`. In HTTPS Server certificates the
common name contains the DNS name of the server.

### 4. Add X509v3 extenstions

```C++
void add_extension(X509 * cert, int id, char const * value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);

    X509_EXTENSION * extension = X509V3_EXT_conf_nid(nullptr, &ctx, id, value);
    X509_add_ext(cert, extension, -1);

    X509_EXTENSION_free(extension);
}

// ...

add_extension(cert, NID_basic_constraints, "critical,CA:TRUE");
add_extension(cert, NID_key_usage, "critical,keyCertSign,cRLSign");
add_extension(cert, NID_subject_key_identifier, "hash");
add_extension(cert, NID_authority_key_identifier, "keyid:always");
```

X509v3 certificates might contain some extensions. One of them is
the `NID_key_usage`, which describes the purpose of the certificate. Some
OpenSSL commands will check the purpose before the actual command is
executed.

### 5. Sign the certificate

```C++
X509_sign(cert, key, EVP_sha256());
```

One every field of the `X509` struct is set, the certificate can be signed.
Every certificate is a signed using the private key of the issuer. Since
this is a self-signed certificate, the previously created private key
is used.

### 6. Write the certificate to PEM file

```C++
file = fopen(filename.c_str(), "wb");
if (file != nullptr)
{
    PEM_write_X509(file, cert);
    fclose(file);
}
```

To store the certificate as PEM file, the function `PEM_write_X509` is used.
