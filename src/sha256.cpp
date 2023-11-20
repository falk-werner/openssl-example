#include <openssl/evp.h>
#include <cstdio>
#include <string>
#include <iostream>

int main(int argc, char* argv[])
{
    OpenSSL_add_all_digests();

    if (argc > 1)
    {
        for(int i = 1; i < argc; i++)
        {
            char const * filename = argv[i];

            EVP_MD_CTX * context = EVP_MD_CTX_create();
            EVP_DigestInit(context, EVP_sha256());

            FILE * file = fopen(filename, "rb");
            if (nullptr != file)
            {
                constexpr size_t const buffer_capacity = 1024;
                char buffer[buffer_capacity];
                size_t buffer_size;

                do
                {
                    buffer_size = fread(buffer, 1, buffer_capacity, file);
                    if (buffer_size > 0)
                    {
                        EVP_DigestUpdate(context, reinterpret_cast<void*>(buffer), buffer_size);
                    }
                } while (buffer_size == buffer_capacity);
                
                fclose(file);
            }

            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hash_length = 0;
            EVP_DigestFinal(context, hash, &hash_length);
            EVP_MD_CTX_free(context);
            
            for (size_t i = 0; i < hash_length; i++)
            {
                printf("%02x", (hash[i] & 0xff));
            }
            printf("\t%s\n", filename);

        }
    }
    else
    {
        std::cout << "usage: sha256 <filename>..." << std::endl;
    }

    EVP_cleanup();
    return EXIT_SUCCESS;
}