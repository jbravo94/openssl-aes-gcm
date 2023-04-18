#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <pthread.h>
#include "thpool.h"
#include "openssl-aes-gcm.hpp"

namespace openssl {

    const static int BUFFER_LENGTH_IN_BYTES = 16;
    const static int START_OF_FILE = 0;
    const static int FWRITE_CHUNK_SIZE = 1;
    const static int MAX_THREADS = 128;

    const static int KEY_LENGTH_IN_BYTES = 32;
    const static int AAD_LENGTH_IN_BYTES = 16;
    const static int IV_LENGTH_IN_BYTES = 16;
    const static int TAG_LENGTH_IN_BYTES = 16;

    const static int PKCS5_PBKDF2_HMAC_SHA1_ITERATIONS = 20000;
    const static int PKCS5_PBKDF2_HMAC_SHA1_SALT_LENGTH = 0;

    const static char READ_BINARY[] = "rb";
    const static char WRITE_BINARY[] = "wb";

    const static char NULL_CHAR = '\0';

    #define DEFAULT_AAD "abcdefghijklmno";

    class AESGCM_INTERNAL {
        public:
            static int encryptFileInternal(FILE *inputFile, FILE *outputFile, unsigned char *key, unsigned char *iv,
                                            unsigned char *aad, unsigned char *tag);
            static int decryptFileInternal(FILE *inputFile, FILE *outputFile, unsigned char *key, unsigned char *iv,
                                         unsigned char *aad, unsigned char *tag);
    };

    struct Params {
        int inputFileDescriptor;
        int outputFileDescriptor;
        unsigned char *key;
    };

    void handleErrors() {
        printf("Some error occured\n");
    }

    int AESGCM::decryptFile(int inputFileDescriptor, int outputFileDescriptor, unsigned char *password) {
        unsigned char key[KEY_LENGTH_IN_BYTES];
        unsigned char tag[TAG_LENGTH_IN_BYTES];
        unsigned char iv[IV_LENGTH_IN_BYTES];
        unsigned char aad[AAD_LENGTH_IN_BYTES] = DEFAULT_AAD;

        if (!PKCS5_PBKDF2_HMAC_SHA1(reinterpret_cast<const char *>(password), strlen(
                reinterpret_cast<const char *const>(password)), nullptr, PKCS5_PBKDF2_HMAC_SHA1_SALT_LENGTH, PKCS5_PBKDF2_HMAC_SHA1_ITERATIONS, KEY_LENGTH_IN_BYTES, key)) {
            printf("Error in key generation\n");
            exit(1);
        }

        FILE *inputFile = fdopen(inputFileDescriptor, READ_BINARY);
        FILE *outputFile = fdopen(outputFileDescriptor, WRITE_BINARY);

        fseek(inputFile, -TAG_LENGTH_IN_BYTES, SEEK_END);
        fread(tag, FWRITE_CHUNK_SIZE, TAG_LENGTH_IN_BYTES, inputFile);

        fseek(inputFile, START_OF_FILE, SEEK_SET);
        fread(aad, FWRITE_CHUNK_SIZE, AAD_LENGTH_IN_BYTES, inputFile);
        fread(iv, FWRITE_CHUNK_SIZE, IV_LENGTH_IN_BYTES, inputFile);

        fflush(inputFile);

        return AESGCM_INTERNAL::decryptFileInternal(inputFile, outputFile, key, iv, aad, tag);
    }

    int AESGCM_INTERNAL::decryptFileInternal(FILE *inputFile, FILE *outputFile, unsigned char *key, unsigned char *iv,
                        unsigned char *aad, unsigned char *tag) {

        fseek(inputFile, START_OF_FILE, SEEK_END);
        long size = ftell(inputFile);

        fseek(inputFile, AAD_LENGTH_IN_BYTES + IV_LENGTH_IN_BYTES, SEEK_SET);

        bool isLastElement = false;

        EVP_CIPHER_CTX *ctx;
        int len = 0, ret;

        if (!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();

        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
            handleErrors();

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH_IN_BYTES, nullptr))
            handleErrors();

        if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv)) handleErrors();

        if (!EVP_DecryptUpdate(ctx, nullptr, &len, aad, AAD_LENGTH_IN_BYTES))
            handleErrors();

        int lastBufferElement;

        unsigned long counter = 0;

        while (!isLastElement) {

            unsigned char buff[BUFFER_LENGTH_IN_BYTES] = {NULL_CHAR };

            for (int i = 0; i < BUFFER_LENGTH_IN_BYTES; i++) {
                counter++;
                lastBufferElement = i;
                int byte = fgetc(inputFile);

                if (byte == EOF || counter == size + 1 - (AAD_LENGTH_IN_BYTES + IV_LENGTH_IN_BYTES + TAG_LENGTH_IN_BYTES)) {
                    isLastElement = true;
                    break;
                } else {
                    buff[i] = byte;
                }
            }

            if (!isLastElement) {
                int enc_len = BUFFER_LENGTH_IN_BYTES;
                unsigned char enc_buff[BUFFER_LENGTH_IN_BYTES] = {NULL_CHAR };

                if (1 != EVP_DecryptUpdate(ctx, enc_buff, &enc_len, buff, BUFFER_LENGTH_IN_BYTES))
                    handleErrors();

                fwrite(enc_buff, FWRITE_CHUNK_SIZE, enc_len, outputFile);
            } else {
                int enc_len = lastBufferElement;
                unsigned char enc_buff[enc_len];

                if (1 != EVP_DecryptUpdate(ctx, enc_buff, &enc_len, buff, enc_len))
                    handleErrors();

                fwrite(enc_buff, FWRITE_CHUNK_SIZE, enc_len - 1, outputFile);

            }
        }

        int enc_len = lastBufferElement;
        unsigned char enc_buff[enc_len];

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LENGTH_IN_BYTES, tag))
            handleErrors();

        ret = EVP_DecryptFinal_ex(ctx, enc_buff, &enc_len);

        if (ret > 0) {
        } else {
            handleErrors();
        }

        EVP_CIPHER_CTX_free(ctx);

        fflush(outputFile);

        return 0;
    }

    int AESGCM::encryptFile(int inputFileDescriptor, int outputFileDescriptor, unsigned char *password) {
        unsigned char key[KEY_LENGTH_IN_BYTES];
        unsigned char tag[TAG_LENGTH_IN_BYTES];
        unsigned char iv[IV_LENGTH_IN_BYTES];
        unsigned char aad[AAD_LENGTH_IN_BYTES] = DEFAULT_AAD;

        if (!PKCS5_PBKDF2_HMAC_SHA1(reinterpret_cast<const char *>(password), strlen(
                reinterpret_cast<const char *const>(password)), nullptr, PKCS5_PBKDF2_HMAC_SHA1_SALT_LENGTH, PKCS5_PBKDF2_HMAC_SHA1_ITERATIONS, KEY_LENGTH_IN_BYTES, key)) {
            printf("Error in key generation\n");
            exit(1);
        }

        while (!RAND_bytes(iv, sizeof(iv)));

        FILE *inputFile = fdopen(inputFileDescriptor, READ_BINARY);
        FILE *outputFile = fdopen(outputFileDescriptor, WRITE_BINARY);

        fwrite(aad, FWRITE_CHUNK_SIZE, AAD_LENGTH_IN_BYTES, outputFile);
        fwrite(iv, FWRITE_CHUNK_SIZE, IV_LENGTH_IN_BYTES, outputFile);
        fflush(outputFile);

        int res = AESGCM_INTERNAL::encryptFileInternal(inputFile, outputFile, key, iv, aad, tag);

        fwrite(tag, FWRITE_CHUNK_SIZE, TAG_LENGTH_IN_BYTES, outputFile);
        fflush(outputFile);

        return res;
    }

    int AESGCM_INTERNAL::encryptFileInternal(FILE *inputFile, FILE *outputFile, unsigned char *key, unsigned char *iv,
                        unsigned char *aad, unsigned char *tag) {

        bool isLastElement = false;

        EVP_CIPHER_CTX *ctx;
        int len = 0;

        if (!(ctx = EVP_CIPHER_CTX_new()))
            handleErrors();

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
            handleErrors();

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH_IN_BYTES, nullptr))
            handleErrors();

        if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv)) handleErrors();

        if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad, AAD_LENGTH_IN_BYTES))
            handleErrors();

        while (!isLastElement) {
            unsigned char buff[BUFFER_LENGTH_IN_BYTES] = {NULL_CHAR };
            int lastBufferElement;

            for (int i = 0; i < BUFFER_LENGTH_IN_BYTES; i++) {
                lastBufferElement = i;
                int byte = fgetc(inputFile);

                if (byte == EOF) {
                    isLastElement = true;
                    break;
                } else {
                    buff[i] = byte;
                }
            }

            if (!isLastElement) {
                int enc_len = BUFFER_LENGTH_IN_BYTES;
                unsigned char enc_buff[BUFFER_LENGTH_IN_BYTES] = { NULL_CHAR };

                if (1 != EVP_EncryptUpdate(ctx, enc_buff, &enc_len, buff, BUFFER_LENGTH_IN_BYTES))
                    handleErrors();

                fwrite(enc_buff, FWRITE_CHUNK_SIZE, enc_len, outputFile);
            } else {
                int enc_len = lastBufferElement + 1;
                unsigned char enc_buff[enc_len];

                if (1 != EVP_EncryptUpdate(ctx, enc_buff, &enc_len, buff, enc_len))
                    handleErrors();

                fwrite(enc_buff, FWRITE_CHUNK_SIZE, enc_len, outputFile);
            }

        }

        int enc_len = BUFFER_LENGTH_IN_BYTES;
        unsigned char enc_buff[BUFFER_LENGTH_IN_BYTES] = {NULL_CHAR };

        if (1 != EVP_EncryptFinal_ex(ctx, enc_buff, &enc_len)) handleErrors();

        for (unsigned char i: enc_buff) {
            if (i == '\0') {
                break;
            }
            fputc(i, outputFile);
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH_IN_BYTES, tag))
            handleErrors();

        EVP_CIPHER_CTX_free(ctx);

        fflush(outputFile);

        return 0;
    }

    void encrypt_p(void *argv) {
        auto *args = (Params *) argv;

        int inputFileDescriptor = args->inputFileDescriptor;
        int outputFileDescriptor = args->outputFileDescriptor;
        unsigned char *key = args->key;

        AESGCM::encryptFile(inputFileDescriptor, outputFileDescriptor, key);
    }

    void decrypt_p(void *argv) {
        auto *args = (Params *) argv;

        int inputFileDescriptor = args->inputFileDescriptor;
        int outputFileDescriptor = args->outputFileDescriptor;
        unsigned char *key = args->key;

        AESGCM::decryptFile(inputFileDescriptor, outputFileDescriptor, key);
    }

    int AESGCM::encryptFiles(int *inputOutputFileDescriptorTuples, int length, unsigned char *key,
                     unsigned int threads) {

        int maxThreads = MAX_THREADS;

        if (threads > maxThreads) {
            printf("Not more that %d threads supported", maxThreads);
            exit(1);
        }

        threadpool thpool = thpool_init(threads);

        for (int i = 0; i < length; i += 2) {
            int inputFileDescriptor = inputOutputFileDescriptorTuples[i];
            int outputFileDescriptor = inputOutputFileDescriptorTuples[i + 1];

            Params params{};
            params.inputFileDescriptor = inputFileDescriptor;
            params.outputFileDescriptor = outputFileDescriptor;
            params.key = key;

            void *args = &params;

            thpool_add_work(thpool, encrypt_p, args);
        }

        thpool_wait(thpool);
        thpool_destroy(thpool);

        return 0;
    }

    int AESGCM::decryptFiles(int *inputOutputFileDescriptorTuples, int length, unsigned char *key,
                     unsigned int threads) {
        int maxThreads = MAX_THREADS;

        if (threads > maxThreads) {
            printf("Not more that %d threads supported", maxThreads);
            exit(1);
        }

        threadpool thpool = thpool_init(threads);

        for (int i = 0; i < length; i += 2) {
            int inputFileDescriptor = inputOutputFileDescriptorTuples[i];
            int outputFileDescriptor = inputOutputFileDescriptorTuples[i + 1];

            Params params{};
            params.inputFileDescriptor = inputFileDescriptor;
            params.outputFileDescriptor = outputFileDescriptor;
            params.key = key;

            void *args = &params;

            thpool_add_work(thpool, decrypt_p, args);
        }

        thpool_wait(thpool);
        thpool_destroy(thpool);

        return 0;
    }

}