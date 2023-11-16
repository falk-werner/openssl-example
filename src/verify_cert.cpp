#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

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
    std::cout << R"(verify_cert, (c) 2023 Falk Werner
Verifies a certificate.

Usage:
    verify_cert [-c <filename>] [-t <filename>] [-u <filename>] [-r <filename>]

Options:
    -c, --certificate <filename> - certifcate to check (default: cert.pem)
    -t, --trusted <filename>     - trusted certificates
    -u, --untrusted <filename>   - untrusted certificates
    -r, --crl <filename>         - certificate revokation list
)";
}

struct context
{
    context(int argc, char * argv[])
    : show_help(false)
    , exit_code(EXIT_SUCCESS)
    , certfile("cert.pem")
    {
        option const long_opts[] = {
            {"certificate", required_argument, nullptr, 'f'},
            {"trusted", required_argument, nullptr, 't'},
            {"untrusted", required_argument, nullptr, 'u'},
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
            int const c = getopt_long(argc, argv, "c:t:u:r:h", long_opts, &option_index);
            switch (c)
            {
                case -1:
                    finished = true;
                    break;
                case 'c':
                    certfile = optarg;
                    break;
                case 't':
                    trusted.push_back(optarg);
                    break;
                case 'u':
                    untrusted.push_back(optarg);
                    break;
                case 'r':
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
    }

    bool show_help;
    int exit_code;
    std::string certfile;
    std::vector<std::string> trusted;
    std::vector<std::string> untrusted;
    std::vector<std::string> crls;
};

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

void verify_cert(
    std::string const & certfile,
    std::vector<std::string> const & trusted,
    std::vector<std::string> const & untrusted,
    std::vector<std::string> crls)
{
    X509 * cert = nullptr;
    FILE * file = fopen(certfile.c_str(), "rb");
    if (nullptr != file)
    {
        PEM_read_X509(file, &cert, nullptr, nullptr);
        fclose(file);
    }
    if (nullptr == cert)
    {
        std::cerr << "error: failed to load certificate" << std::endl;
        return;
    }

    STACK_OF(X509) * trusted_certs = load_certs(trusted);
    STACK_OF(X509) * untrusted_certs = load_certs(untrusted);
    STACK_OF(X509_CRL) * revoked = load_crls(crls);

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

    X509_STORE_CTX_free(store);
    sk_X509_CRL_pop_free(revoked, X509_CRL_free);
    sk_X509_pop_free(untrusted_certs, X509_free);    
    sk_X509_pop_free(trusted_certs, X509_free);    
    X509_free(cert);
}

}

int main(int argc, char* argv[])
{
    context ctx(argc, argv);
    if (!ctx.show_help)
    {
        verify_cert(ctx.certfile, ctx.trusted, ctx.untrusted, ctx.crls);
    }
    else
    {
        print_usage();
    }

    return ctx.exit_code;
}
