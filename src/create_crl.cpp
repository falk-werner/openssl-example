// SPDX-License-Identifier: Unlicense

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <getopt.h>

#include <ctime>
#include <cstdlib>
#include <cstdio>

#include <string>
#include <iostream>
#include <filesystem>

namespace
{

void print_usage()
{
    std::cout << R"(create_crl, (c) 2023 Falk Werner
Creates a certificate revokation list (CRL).

Usage:
    create_crl [-f <filename>] [-i <filename>] [-k <filename>] [-c <filename>]

Options:
    -f, --filename <filename>    - name of the generated CRL file (default: crl.pem)
    -i, --issuer   <filename>    - name of the issuers certificate (default: issuer.pem)
    -k, --keyfile  <filename>    - name of the issuers private key (default: issuer.key)
    -c, --certificate <filename> - name of certificate to revoke (default: cert.pem)

Example:
    creat_crl -f crl.pem
)";
}

struct context
{
    context(int argc, char * argv[])
    : show_help(false)
    , exit_code(EXIT_SUCCESS)
    , filename("crl.pem")
    , certfile("cert.pem")
    , issuer("issuer.pem")
    , keyfile("issuer.key")
    {
        option const long_opts[] = {
            {"filename", required_argument, nullptr, 'f'},
            {"certificate", required_argument, nullptr, 'c'},
            {"issuer", required_argument, nullptr, 'i'},
            {"keyfile", required_argument, nullptr, 'k'},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, 0, nullptr, 0}
        };

        opterr = 0;
        optind = 0;

        bool finished = false;
        while (!finished)
        {
            int option_index = 0;
            int const c = getopt_long(argc, argv, "f:c:k:i:h", long_opts, &option_index);
            switch (c)
            {
                case -1:
                    finished = true;
                    break;
                case 'f':
                    filename = optarg;
                    break;
                case 'c':
                    certfile = optarg;
                    break;
                case 'k':
                    keyfile = optarg;
                    break;
                case 'i':
                    issuer = optarg;
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
    std::string certfile;
    std::string issuer;
    std::string keyfile;
};

void create_crl(
    std::string const & filename,
    std::string const & certfile,
    std::string const & issuer,
    std::string const & keyfile
)
{
    X509_CRL * crl = nullptr;
    FILE * file;

    if (std::filesystem::is_regular_file(filename))
    {
        file = fopen(filename.c_str(), "rb");
        if (nullptr != file)
        {
            PEM_read_X509_CRL(file, &crl, nullptr, nullptr);
            fclose(file);
        }
        if (nullptr == file)
        {
            std::cerr << "error: failed to load CRL" << std::endl;
            return;
        }
    }
    else
    {
        crl = X509_CRL_new();        
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
        std::cerr << "error: failed to load issuer certificate" << std::endl;
        X509_CRL_free(crl);
        return;
    }

    EVP_PKEY * key = nullptr;
    file = fopen(keyfile.c_str(), "rb");
    if (nullptr != file)
    {
        PEM_read_PrivateKey(file, &key, nullptr, nullptr);
        fclose(file);
    }
    if (nullptr == key)
    {
        std::cerr << "error: failed to load issuer key" << std::endl;
        X509_free(issuer_cert);
        X509_CRL_free(crl);
        return;
    }

    X509 * cert = nullptr;
    file = fopen(certfile.c_str(), "rb");
    if (nullptr != file)
    {
        PEM_read_X509(file, &cert, nullptr, nullptr);
        fclose(file);
    }
    if (nullptr == cert)
    {
        std::cerr << "error: failed to load certificate" << std::endl;
        EVP_PKEY_free(key);
        X509_free(issuer_cert);
        X509_CRL_free(crl);
        return;
    }

    X509_CRL_set_version(crl, X509_CRL_VERSION_2);
    X509_CRL_set_issuer_name(crl, X509_get_issuer_name(issuer_cert));

    ASN1_TIME * lastUpdate = ASN1_TIME_new();
    X509_gmtime_adj(lastUpdate, 0);
	X509_CRL_set_lastUpdate(crl, lastUpdate);
    ASN1_TIME_free(lastUpdate);

    ASN1_TIME * nextUpdate = ASN1_TIME_new();
    X509_gmtime_adj(nextUpdate, 60 * 60 * 24 * 10);
	X509_CRL_set_nextUpdate(crl, nextUpdate);
    ASN1_TIME_free(nextUpdate);


    X509_REVOKED * revoked = X509_REVOKED_new();
    ASN1_TIME * revoked_at = ASN1_TIME_new();
    X509_gmtime_adj(revoked_at, 0);
    X509_REVOKED_set_revocationDate(revoked, revoked_at);
    ASN1_TIME_free(revoked_at);

    X509_REVOKED_set_serialNumber(revoked, X509_get_serialNumber(cert));
    X509_CRL_add0_revoked(crl, revoked);

    X509_CRL_sort(crl);
    X509_CRL_sign(crl, key, EVP_sha256());

    file = fopen(filename.c_str(), "wb");
    if (nullptr != file)
    {
        PEM_write_X509_CRL(file, crl);
        fclose(file);
    }

    X509_free(cert);
    EVP_PKEY_free(key);
    X509_free(issuer_cert);
    X509_CRL_free(crl);
}

}

int main(int argc, char * argv[])
{
    context ctx(argc, argv);
    if (!ctx.show_help)
    {
        create_crl(ctx.filename, ctx.certfile, ctx.issuer, ctx.keyfile);
    }
    else
    {
        print_usage();
    }

    return ctx.exit_code;

}