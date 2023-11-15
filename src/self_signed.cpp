#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <getopt.h>

#include <cstdlib>
#include <cstdio>

#include <string>
#include <iostream>

namespace
{

void print_usage()
{
    std::cout << R"(self_signed, (c) 2023 Falk Werner
Creates a self-signed certificate.

Usage:
    self_signed [-f <filename>] [-k <filename>] [-d <days>] [-c <common name>]

Options:
    -f, --filename <filename>       - specify the name of generated file (default: self-signed.pem)
    -k, --keyfile  <filename>       - specify the name of generated private key (default: self-signed.key)
    -d, --days <days>               - number of days the certificate is valid (default: 10)
    -c, --common-name <common name> - common name of the certificate (default: Self-Signed)

Example:
    self_signed -f cert.pem
)";
}

struct context
{
    context(int argc, char * argv[])
    : show_help(false)
    , exit_code(EXIT_SUCCESS)
    , filename("self-signed.pem")
    , keyfile("self-signed.key")
    , days(10)
    , common_name("Self Signed")
    {
        option const long_opts[] = {
            {"filename", required_argument, nullptr, 'f'},
            {"keyfile", required_argument, nullptr, 'k'},
            {"days", required_argument, nullptr, 'd'},
            {"common-name", required_argument, nullptr, 'c'},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, 0, nullptr, 0}
        };

        opterr = 0;
        optind = 0;

        bool finished = false;
        while (!finished)
        {
            int option_index = 0;
            int const c = getopt_long(argc, argv, "f:k:d:c:h", long_opts, &option_index);
            switch (c)
            {
                case -1:
                    finished = true;
                    break;
                case 'f':
                    filename = optarg;
                    break;
                case 'k':
                    keyfile = optarg;
                    break;
                case 'd':
                    days = std::stoi(optarg);
                    break;
                case 'c':
                    common_name = optarg;
                    break;
                case 'h':
                    show_help = true;
                    finished = true;
                    break;
                default:
                    std::cerr << "error: invalid command line option" << std::endl;
                    exit_code = EXIT_FAILURE;
                    show_help = true;
                    finished = true;
                    break;
            }
        }
    }

    bool show_help;
    int exit_code;
    std::string filename;
    std::string keyfile;
    int days;
    std::string common_name;
};

void add_extension(X509 * cert, int id, char const * value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);

    X509_EXTENSION * extension = X509V3_EXT_conf_nid(nullptr, &ctx, id, value);
    X509_add_ext(cert, extension, -1);

    X509_EXTENSION_free(extension);
}

void add_entry_by_NID(X509_NAME * name, int id, std::string const & value)
{
    X509_NAME_add_entry_by_NID(name, id, MBSTRING_UTF8, (unsigned char const *) value.c_str(), -1, -1, 0);
}

void create_certificate(
    std::string const & filename,
    std::string const & keyfile,
    int days_valid,
    std::string const & common_name)
{
    EVP_PKEY * key = EVP_RSA_gen(4096);
    FILE * file = fopen(keyfile.c_str(), "wb");
    if (nullptr != file)
    {
        PEM_write_PrivateKey(file, key, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(file);
    }

    X509 * cert = X509_new();
    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1L);
    X509_gmtime_adj(X509_get_notBefore(cert), 0L);
    X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60L * 24L * days_valid);
    X509_set_pubkey(cert, key);

    X509_NAME * subject = X509_NAME_new();
    add_entry_by_NID(subject, NID_domainComponent, "org");
    add_entry_by_NID(subject, NID_domainComponent, "exampe");
    add_entry_by_NID(subject, NID_organizationName, "Example org");
    add_entry_by_NID(subject, NID_organizationalUnitName, "Example Root CA");
    add_entry_by_NID(subject, NID_commonName, common_name);
    X509_set_subject_name(cert, subject);
    X509_set_issuer_name(cert, subject);

    add_extension(cert, NID_basic_constraints, "critical,CA:TRUE");
    add_extension(cert, NID_key_usage, "critical,keyCertSign,cRLSign");
    add_extension(cert, NID_subject_key_identifier, "hash");
    add_extension(cert, NID_authority_key_identifier, "keyid:always");

    X509_sign(cert, key, EVP_sha256());

    file = fopen(filename.c_str(), "wb");
    if (file != nullptr)
    {
        PEM_write_X509(file, cert);
        fclose(file);
    }

    X509_NAME_free(subject);
    X509_free(cert);
    EVP_PKEY_free(key);
}

}


int main(int argc, char* argv[])
{
    context ctx(argc, argv);
    if (!ctx.show_help)
    {
        create_certificate(ctx.filename, ctx.keyfile, ctx.days, ctx.common_name);
    }
    else
    {
        print_usage();
    }

    return ctx.exit_code;
}
