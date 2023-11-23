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
    std::cout << R"(sign_csr, (c) 2023 Falk Werner
Sign a certificate signing request.

Usage:
    sign_csr [-f <filename>] [-c <filename>] [-k <filename>] [-i <filename>]

Options:
    -f, --filename <filename> - specify the name of generated file (default: subject.pem)
    -c, --csr      <filename> - specify the name the csr file (default: subject.csr)
    -k, --keyfile  <filename> - specify the name issuer key file (default: issuer.key)
    -i, --issuer   <filename> - specify the name the issuer certificate (default: issuer.pem)

Example:
    sign_csr -f alice.pem -c alice.csr -i root.pem -k root.key 
)";
}

struct context
{
    context(int argc, char * argv[])
    : show_help(false)
    , exit_code(EXIT_SUCCESS)
    , csrfile("subject.csr")
    , filename("subject.pem")
    , keyfile("issuer.key")
    , issuer("issuer.pem")
    {
        option const long_opts[] = {
            {"filename", required_argument, nullptr, 'f'},
            {"csr", required_argument, nullptr, 'c'},
            {"keyfile", required_argument, nullptr, 'k'},
            {"issuer", required_argument, nullptr, 'i'},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, 0, nullptr, 0}
        };

        opterr = 0;
        optind = 0;

        bool finished = false;
        while (!finished)
        {
            int option_index = 0;
            int const c = getopt_long(argc, argv, "f:k:i:c:h", long_opts, &option_index);
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
                case 'i':
                    issuer = optarg;
                    break;
                case 'c':
                    csrfile = optarg;
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
    std::string csrfile;
    std::string filename;
    std::string keyfile;
    std::string issuer;
};

void sign_csr(
    std::string const & csrfile,
    std::string const & filename,
    std::string const & issuer,
    std::string const & keyfile)
{

    EVP_PKEY * key = nullptr;
    FILE * file = fopen(keyfile.c_str(), "rb");
    if (nullptr != file)
    {
        PEM_read_PrivateKey(file, &key, nullptr, nullptr);
        fclose(file);
    }
    if (nullptr == key)
    {
        std::cerr << "error: failed to read issuer key" << std::endl;
        return;
    }

    X509 * issuer_cert = nullptr;
    file = fopen(issuer.c_str(), "rb");
    if (nullptr != file)
    {
        PEM_read_X509(file, &issuer_cert, nullptr, nullptr);
        fclose(file);
    }
    if (nullptr == issuer_cert)
    {
        std::cerr << "error: failed to read issuer certificate" << std::endl;
        EVP_PKEY_free(key);
        return;
    }

    X509_REQ * csr = nullptr;
    file = fopen(csrfile.c_str(), "rb");
    if (nullptr != file)
    {
        PEM_read_X509_REQ(file, &csr, nullptr, nullptr);
        fclose(file);
    }
    if (nullptr == csr)
    {
        std::cerr << "error: failed to read CSR file" << std::endl;
        X509_free(issuer_cert);
        EVP_PKEY_free(key);
        return;
    }
    if (1 != X509_REQ_verify(csr, X509_REQ_get0_pubkey(csr)))
    {
        std::cerr << "error: failed to verify CSR" << std::endl;
        X509_REQ_free(csr);
        X509_free(issuer_cert);
        EVP_PKEY_free(key);
        return;
    }

    X509 * cert = X509_new();
    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1L);
    X509_gmtime_adj(X509_get_notBefore(cert), 0L);
    X509_gmtime_adj(X509_get_notAfter(cert), 60L * 60L * 24L * 10L);    
    X509_set_pubkey(cert, X509_REQ_get0_pubkey(csr));

    X509_set_subject_name(cert, X509_REQ_get_subject_name(csr));
    X509_set_issuer_name(cert, X509_get_subject_name(issuer_cert));

    STACK_OF(X509_EXTENSION) * extensions = X509_REQ_get_extensions(csr);
    X509_EXTENSION * extension = sk_X509_EXTENSION_pop(extensions);
    while (nullptr != extension)
    {
        X509_add_ext(cert, extension, -1);
        extension = sk_X509_EXTENSION_pop(extensions);
    }

    X509_sign(cert, key, EVP_sha256());
    file = fopen(filename.c_str(), "wb");
    if (file != nullptr)
    {
        PEM_write_X509(file, cert);
        fclose(file);
    }

    X509_free(cert);
    X509_REQ_free(csr);
    X509_free(issuer_cert);
    EVP_PKEY_free(key);
}


}

int main(int argc, char* argv[])
{
    context ctx(argc, argv);
    if (!ctx.show_help)
    {
        sign_csr(ctx.csrfile, ctx.filename, ctx.issuer, ctx.keyfile);
    }
    else
    {
        print_usage();
    }

    return ctx.exit_code;
}
