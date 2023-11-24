// SPDX-License-Identifier: Unlicense

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <cstdlib>
#include <cstdio>

#include <string>
#include <vector>
#include <iostream>
#include <filesystem>
#include <memory>

using std::filesystem::path;


namespace
{
constexpr long const valid_duration = 60L * 60L * 24L * 10L;

void create_dirs(path const & base_path)
{
    using std::filesystem::create_directory;

    create_directory(base_path);
    create_directory(base_path / "root_ca");
    create_directory(base_path / "signing_ca");
    create_directory(base_path / "alice");
    create_directory(base_path / "bob");
    create_directory(base_path / "charlie");
    create_directory(base_path / "donny");
}

using X509_ptr = std::unique_ptr<X509, void(*)(X509*)>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)>;
using X509_NAME_ptr = std::unique_ptr<X509_NAME, void(*)(X509_NAME*)>;

EVP_PKEY_ptr create_key(path const & filename)
{
    constexpr int const keysize = 4096;
    EVP_PKEY_ptr key = {EVP_RSA_gen(keysize), EVP_PKEY_free};
    FILE * file = fopen(filename.c_str(), "wb");
    if (nullptr != file)
    {
        PEM_write_PrivateKey(file, key.get(), nullptr, nullptr, 0, nullptr, nullptr);
        fclose(file);
    }

    return key;
}

void add_entry_by_NID(X509_NAME * name, int id, std::string const & value)
{
    X509_NAME_add_entry_by_NID(name, id, MBSTRING_UTF8, (unsigned char const *) value.c_str(), -1, -1, 0);
}

X509_NAME_ptr create_name(std::string common_name)
{
    X509_NAME * name = X509_NAME_new();
    add_entry_by_NID(name, NID_domainComponent, "org");
    add_entry_by_NID(name, NID_domainComponent, "exampe");
    add_entry_by_NID(name, NID_organizationName, "Example org");
    add_entry_by_NID(name, NID_organizationalUnitName, "CA Department");
    add_entry_by_NID(name, NID_commonName, common_name);

    return {name, X509_NAME_free};
}

void add_extension(X509 * cert, int id, char const * value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);

    X509_EXTENSION * extension = X509V3_EXT_conf_nid(nullptr, &ctx, id, value);
    X509_add_ext(cert, extension, -1);

    X509_EXTENSION_free(extension);
}

X509_ptr create_root_cert(path filename, EVP_PKEY * key)
{
    X509 * cert = X509_new();
    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1L);
    X509_gmtime_adj(X509_get_notBefore(cert), 0L);
    X509_gmtime_adj(X509_get_notAfter(cert), valid_duration);
    X509_set_pubkey(cert, key);

    X509_NAME_ptr subject = create_name("Root CA");
    X509_set_subject_name(cert, subject.get());
    X509_set_issuer_name(cert, subject.get());

    add_extension(cert, NID_basic_constraints, "critical,CA:TRUE");
    add_extension(cert, NID_key_usage, "critical,keyCertSign,cRLSign");
    add_extension(cert, NID_subject_key_identifier, "hash");
    add_extension(cert, NID_authority_key_identifier, "keyid:always");

    X509_sign(cert, key, EVP_sha256());

    FILE * file = fopen(filename.c_str(), "wb");
    if (file != nullptr)
    {
        PEM_write_X509(file, cert);
        fclose(file);
    }

    return {cert, X509_free};
}

X509_ptr create_ca_cert(
    std::string common_name,
    path filename,
    EVP_PKEY * key,
    X509 * issuer_cert,
    EVP_PKEY * issuer_key)
{
    X509 * cert = X509_new();
    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1L);
    X509_gmtime_adj(X509_get_notBefore(cert), 0L);
    X509_gmtime_adj(X509_get_notAfter(cert), valid_duration);
    X509_set_pubkey(cert, key);

    X509_NAME_ptr subject = create_name(common_name);
    X509_set_subject_name(cert, subject.get());
    X509_set_issuer_name(cert, X509_get_subject_name(issuer_cert));

    add_extension(cert, NID_basic_constraints, "critical,CA:TRUE");
    add_extension(cert, NID_key_usage, "critical,keyCertSign,cRLSign");
    add_extension(cert, NID_subject_key_identifier, "hash");

    X509_sign(cert, issuer_key, EVP_sha256());

    FILE * file = fopen(filename.c_str(), "wb");
    if (file != nullptr)
    {
        PEM_write_X509(file, cert);
        fclose(file);
    }

    return {cert, X509_free};
}

void create_cert(
    std::string common_name,
    path base_path,
    long serial,
    X509 * issuer_cert,
    EVP_PKEY * issuer_key)
{
    EVP_PKEY_ptr key = create_key(base_path / (common_name + ".key"));

    X509 * cert = X509_new();
    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
    X509_gmtime_adj(X509_get_notBefore(cert), 0L);
    X509_gmtime_adj(X509_get_notAfter(cert), valid_duration);
    X509_set_pubkey(cert, key.get());

    X509_NAME_ptr subject = create_name(common_name);
    X509_set_subject_name(cert, subject.get());
    X509_set_issuer_name(cert, X509_get_subject_name(issuer_cert));

    add_extension(cert, NID_basic_constraints, "critical,CA:TRUE");
    add_extension(cert, NID_key_usage, "critical,keyCertSign,cRLSign,digitalSignature");
    add_extension(cert, NID_subject_key_identifier, "hash");

    X509_sign(cert, issuer_key, EVP_sha256());

    path const & filename = base_path / (common_name + ".pem");
    FILE * file = fopen(filename.c_str(), "wb");
    if (file != nullptr)
    {
        PEM_write_X509(file, cert);
        fclose(file);
    }

    X509_free(cert);
}

void add_req_extension(STACK_OF(X509_EXTENSION) * stack, X509_REQ * req, int id, char const * value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, nullptr, nullptr, req, nullptr, 0);
    X509_EXTENSION * extension = X509V3_EXT_conf_nid(nullptr, &ctx, id, value);
    sk_X509_EXTENSION_push(stack, extension);
}

void create_csr(
    std::string common_name,
    path base_path)
{
    EVP_PKEY_ptr key = create_key(base_path / (common_name + ".key"));

    X509_REQ * csr = X509_REQ_new();
    X509_REQ_set_version(csr, X509_REQ_VERSION_1);
    X509_REQ_set_pubkey(csr, key.get());

    X509_NAME_ptr subject = create_name(common_name);
    X509_REQ_set_subject_name(csr, subject.get());

    STACK_OF(X509_EXTENSION) * extensions = sk_X509_EXTENSION_new(nullptr);
    add_req_extension(extensions, csr, NID_basic_constraints, "critical,CA:TRUE");
    add_req_extension(extensions, csr, NID_key_usage, "critical,keyCertSign,cRLSign,digitalSignature");
    add_req_extension(extensions, csr, NID_subject_key_identifier, "hash");

    X509_REQ_add_extensions(csr, extensions);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);

    X509_REQ_sign(csr, key.get(), EVP_sha256());

    path const & filename = base_path / (common_name + ".csr");
    FILE * file = fopen(filename.c_str(), "wb");
    if (file != nullptr)
    {
        PEM_write_X509_REQ(file, csr);
        fclose(file);
    }

    X509_REQ_free(csr);
}

void create_crl(
    path filename,
    std::vector<long> serials,
    X509 * issuer_cert,
    EVP_PKEY * issuer_key)
{
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

    for(auto const serial: serials) {
        X509_REVOKED * revoked = X509_REVOKED_new();

        ASN1_TIME * revoked_at = ASN1_TIME_new();
        X509_gmtime_adj(revoked_at, 0);
        X509_REVOKED_set_revocationDate(revoked, revoked_at);
        ASN1_TIME_free(revoked_at);

        ASN1_INTEGER * serial_holder = ASN1_INTEGER_new();
        ASN1_INTEGER_set(serial_holder, serial);
        X509_REVOKED_set_serialNumber(revoked, serial_holder);
        ASN1_INTEGER_free(serial_holder);

        X509_CRL_add0_revoked(crl, revoked);
    }

    X509_CRL_sort(crl);
    X509_CRL_sign(crl, issuer_key, EVP_sha256());

    FILE * file = fopen(filename.c_str(), "wb");
    if (nullptr != file)
    {
        PEM_write_X509_CRL(file, crl);
        fclose(file);
    }

    X509_CRL_free(crl);
}

}

int main(int argc, char* argv[])
{
    (void) argc;
    (void) argv;

    path const base_path("test-pki");
    create_dirs(base_path);
    
    EVP_PKEY_ptr root_key = create_key(base_path / "root_ca" / "root_ca.key");
    X509_ptr root_cert = create_root_cert(base_path / "root_ca" / "root_ca.pem", root_key.get());

    EVP_PKEY_ptr signing_key = create_key(base_path / "signing_ca" / "signing_ca.key");
    X509_ptr signing_ca = create_ca_cert("Signing CA", base_path / "signing_ca" / "signing_ca.pem",
        signing_key.get(), root_cert.get(), root_key.get());

    create_cert("alice"  , base_path / "alice"  , 1, signing_ca.get(), signing_key.get());
    create_cert("bob"    , base_path / "bob"    , 2, signing_ca.get(), signing_key.get());
    create_cert("charlie", base_path / "charlie", 3, signing_ca.get(), signing_key.get());

    create_crl(base_path / "signing_ca" / "signing_ca.crl", {3}, signing_ca.get(), signing_key.get());

    create_csr("donny", base_path / "donny");

    return EXIT_SUCCESS;
}
