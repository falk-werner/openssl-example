// SPDX-License-Identifier: Unlicense

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
    std::cout << R"(create_csr, (c) 2023 Falk Werner
Creates a certificate signing request.

Usage:
    create_csr [-f <filename>] [-k <filename>] [-c <common name>]

Options:
    -f, --filename <filename>       - specify the name of generated file (default: req.pem)
    -k, --keyfile  <filename>       - specify the name of generated private key (default: req.key)
    -c, --common-name <common name> - common name of the csr (default: Req)

Example:
    create_csr -f signing-ca.csr -k signing-ca.key

)";
}

struct context
{
    context(int argc, char * argv[])
    : show_help(false)
    , exit_code(EXIT_SUCCESS)
    , filename("req.csr")
    , keyfile("req.key")
    , common_name("Req")
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
            int const c = getopt_long(argc, argv, "f:k:c:h", long_opts, &option_index);
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
    std::string common_name;
};

void add_entry_by_NID(X509_NAME * name, int id, std::string const & value)
{
    X509_NAME_add_entry_by_NID(name, id, MBSTRING_UTF8, (unsigned char const *) value.c_str(), -1, -1, 0);
}

void add_extension(STACK_OF(X509_EXTENSION) * stack, X509_REQ * req, int id, char const * value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, nullptr, nullptr, req, nullptr, 0);
    X509_EXTENSION * extension = X509V3_EXT_conf_nid(nullptr, &ctx, id, value);
    sk_X509_EXTENSION_push(stack, extension);
}

void create_csr(
    std::string const & filename,
    std::string const & keyfile,
    std::string const & common_name)
{
    EVP_PKEY * key = EVP_RSA_gen(4096);
    FILE * file = fopen(keyfile.c_str(), "wb");
    if (nullptr != file)
    {
        PEM_write_PrivateKey(file, key, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(file);
    }

    X509_REQ * req = X509_REQ_new();
    X509_REQ_set_version(req, X509_REQ_VERSION_1);
    X509_REQ_set_pubkey(req, key);

    X509_NAME * subject = X509_NAME_new();
    add_entry_by_NID(subject, NID_domainComponent, "org");
    add_entry_by_NID(subject, NID_domainComponent, "exampe");
    add_entry_by_NID(subject, NID_organizationName, "Example org");
    add_entry_by_NID(subject, NID_organizationalUnitName, "Example CSR");
    add_entry_by_NID(subject, NID_commonName, common_name.c_str());
    X509_REQ_set_subject_name(req, subject);

    STACK_OF(X509_EXTENSION) * extensions = sk_X509_EXTENSION_new(nullptr);
    add_extension(extensions, req, NID_basic_constraints, "critical,CA:TRUE");
    add_extension(extensions, req, NID_key_usage, "critical,keyCertSign,cRLSign,digitalSignature");
    add_extension(extensions, req, NID_subject_key_identifier, "hash");

    X509_REQ_add_extensions(req, extensions);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);

    X509_REQ_sign(req, key, EVP_sha256());
    file = fopen(filename.c_str(), "wb");
    if (nullptr != file)
    {
        PEM_write_X509_REQ(file, req);
        fclose(file);
    }

    X509_NAME_free(subject);
    X509_REQ_free(req);
    EVP_PKEY_free(key);
}

}

int main(int argc, char * argv[])
{
    context ctx(argc, argv);
    if (!ctx.show_help)
    {
        create_csr(ctx.filename, ctx.keyfile, ctx.common_name);
    }
    else
    {
        print_usage();
    }

    return ctx.exit_code;
}
