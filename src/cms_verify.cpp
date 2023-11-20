// SPDX-License-Identifier: Unlicense

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/bio.h>

#include <getopt.h>

#include <cstdlib>
#include <cstdio>

#include <string>
#include <vector>
#include <iostream>

namespace
{

void print_usage()
{
    std::cout << R"(cms_verify, (c) 2023 Falk Werner
Verifies a files signature using CMS.

Usage:
    cms_verify -f <filename> [-s <filename>] [-t filename] [-c <filename>]

Options:
    -f, --filename  - path of the file containing the data (required)
    -s, --signature - path of the file containing the signature (default: <data file>.sig)
    -t, --trusted   - path of a trusted certificate
    -c, --crl       - path of a CRL file
)";
}

struct context
{
    context(int argc, char * argv[])
    : show_help(false)
    , exit_code(EXIT_SUCCESS)
    {
        option const long_opts[] = {
            {"filename", required_argument, nullptr, 'f'},
            {"signature", required_argument, nullptr, 's'},
            {"trusted", required_argument, nullptr, 't'},
            {"crl", required_argument, nullptr, 'r'},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, 0, nullptr, 0}
        };

        opterr = 0;
        optind = 0;

        bool finished = false;
        while (!finished)
        {
            int option_index = 0;
            int const c = getopt_long(argc, argv, "f:s:t:c:h", long_opts, &option_index);
            switch (c)
            {
                case -1:
                    finished = true;
                    break;
                case 'f':
                    data_file = optarg;
                    break;
                case 's':
                    signature_file = optarg;
                    break;
                case 't':
                    trusted.push_back(optarg);
                    break;
                case 'c':
                    crls.push_back(optarg);
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

        if ((!show_help) && (data_file.empty()))
        {
            std::cerr << "error: missing data file (-f)" << std::endl;
            show_help = true;
            exit_code = EXIT_FAILURE;
        }

        if ((!show_help) && (signature_file.empty()))
        {
            signature_file = data_file + ".sig";
        }
    }

    bool show_help;
    int exit_code;
    std::string data_file;
    std::string signature_file;
    std::vector<std::string> trusted;
    std::vector<std::string> crls;
};


void cms_verify(
    std::string const & signature_file,
    std::string const & data_file,
    std::vector<std::string> const & trusted_certfiles,
    std::vector<std::string> const & crl_files)
{
    CMS_ContentInfo * cms = nullptr;
    FILE * file = fopen(signature_file.c_str(), "rb");
    if (nullptr != file)
    {
        PEM_read_CMS(file, &cms, nullptr, nullptr);
        fclose(file);
    }
    if (nullptr == cms)
    {
        std::cerr << "error: failed to read signature" << std::endl;
        return;
    }

    BIO * data = BIO_new_file(data_file.c_str(),"rb");
    if (nullptr == data)
    {
        std::cerr << "error: failed to read data file" << std::endl;
        CMS_ContentInfo_free(cms);
        return;
    }


    X509_STORE * store = X509_STORE_new();

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
        }
    }

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
            }
        }

        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK_ALL);
    }


    int const result = CMS_verify(cms, nullptr, store, data, nullptr, CMS_DETACHED);
    if (result == 1)
    {

        std::cout << "OK" << std::endl;
    }
    else
    {
        std::cout << "verifcation failed" << std::endl;
    }

    X509_STORE_free(store);
    BIO_free(data);
    CMS_ContentInfo_free(cms);
}

}

int main(int argc, char * argv[])
{
    context ctx(argc, argv);
    if (!ctx.show_help)
    {
        cms_verify(ctx.signature_file, ctx.data_file, ctx.trusted, ctx.crls);
    }
    else
    {
        print_usage();
    }

    return ctx.exit_code;
}