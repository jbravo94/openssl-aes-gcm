#ifndef gcm_h
#define gcm_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

namespace openssl {

    class AESGCM {

        public:

            static int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
                        int aad_len, unsigned char *key, unsigned char *iv,
                        unsigned char *ciphertext, unsigned char *tag) {
                return 0;
            }

            static int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
                        int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
                        unsigned char *plaintext) {
                return 0;
            }

            static int encryptFile(int inputFileDescriptor, int outputFileDescriptor, unsigned char *key);


            static int decryptFile(int inputFileDescriptor, int outputFileDescriptor, unsigned char *key);


            static int encryptFiles(int *inputOutputFileDescriptorTuples, int length, unsigned char *key,
                             unsigned int threads);

            static int decryptFiles(int *inputOutputFileDescriptorTuples, int length, unsigned char *key,
                             unsigned int threads);
    };
}

#endif