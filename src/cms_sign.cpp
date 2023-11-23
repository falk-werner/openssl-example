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
    std::cout << R"(cms_sign, (c) 2023 Falk Werner
Signs a file using CMS.

Usage:
    cms_sign [-f <filename>] [-s <cfilename>] [-k <filename>]

Options:
    -f, --filename <filename>  - file to sign
    -s, --signer <filename>    - signer certificate
    -k, --keyfile <filename>   - signer key
)";
}

struct context
{
    context(int argc, char * argv[])
    : show_help(false)
    , exit_code(EXIT_SUCCESS)
    {
        option const long_opts[] =
        {
            {"filename", required_argument, nullptr, 'f'},
            {"signer", required_argument, nullptr, 's'},
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
            int const c = getopt_long(argc, argv, "f:s:k:h", long_opts, &option_index);
            switch (c)
            {
                case -1:
                    finished = true;
                    break;
                case 'f':
                    filename = optarg;
                    break;
                case 's':
                    signers.push_back(optarg);
                    break;
                case 'k':
                    signer_keys.push_back(optarg);
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

        if ((!show_help) && filename.empty())
        {
            std::cerr << "error: missing filename" << std::endl;
            show_help = true;
            exit_code = EXIT_FAILURE;
        }

        if ((!show_help) && signers.empty())
        {
            std::cerr << "error: missing signer" << std::endl;
            show_help = true;
            exit_code = EXIT_FAILURE;
        }

        if ((!show_help) && signer_keys.empty())
        {
            std::cerr << "error: missing signer key" << std::endl;
            show_help = true;
            exit_code = EXIT_FAILURE;
        }

        if ((!show_help) && (signers.size() != signer_keys.size()))
        {
            std::cerr << "error: signers and sign keys do not align" << std::endl;
            show_help = true;
            exit_code = EXIT_FAILURE;
        }
    }

    bool show_help;
    int exit_code;
    std::string filename;
    std::vector<std::string> signers;
    std::vector<std::string> signer_keys;
};

void cms_sign(
    std::string const & filename,
    std::vector<std::string> const & signers,
    std::vector<std::string> const & signer_keys
)
{
    FILE * file;
    BIO * bio = BIO_new_file(filename.c_str(), "rb");
    if (!bio)
    {
        std::cerr << "error: failed to open file" << std::endl;
        return;
    }

    int flags = CMS_DETACHED ;
    CMS_ContentInfo * info = CMS_sign(nullptr, nullptr, nullptr, bio, flags | CMS_PARTIAL);

    for(size_t i = 0; i < signers.size(); i++)
    {
        X509 * additional_signer = nullptr;
        file = fopen(signers[i].c_str(), "rb");
        if (nullptr != file)
        {
            PEM_read_X509(file, &additional_signer, nullptr, nullptr);
            fclose(file);
        }
        if (nullptr == additional_signer)
        {
            std::cout << "error: warning: failed to load additional signer \'" << signers[i] << "\': skip" << std::endl; 
            continue;
        }

        EVP_PKEY * additional_key = nullptr;
        file = fopen(signer_keys[i].c_str(), "rb");
        if (nullptr != file)
        {
            PEM_read_PrivateKey(file, &additional_key, nullptr, nullptr);
            fclose(file);
        }
        if (nullptr == additional_key)
        {
            std::cout << "error: warning: failed to load additional key \'" << signer_keys[i] << "\': skip" << std::endl;
            X509_free(additional_signer);
            continue;
        }

        CMS_add1_signer(info, additional_signer, additional_key, nullptr, flags | CMS_PARTIAL);

        EVP_PKEY_free(additional_key);
        X509_free(additional_signer);
    }

    CMS_final(info, bio, nullptr, flags);

    file = fopen((filename + ".sig").c_str(), "wb");
    if (nullptr != file)
    {
        PEM_write_CMS(file, info);
        fclose(file);
    }
    else
    {
        std::cout << "error: failed to write signature" << std::endl;
    }

    CMS_ContentInfo_free(info);
    BIO_free(bio);
}

}

int main(int argc, char * argv[])
{
    context ctx(argc, argv);

    if (!ctx.show_help)
    {
        cms_sign(ctx.filename, ctx.signers, ctx.signer_keys);       
    }
    else
    {
        print_usage();
    }

    return ctx.exit_code;
}