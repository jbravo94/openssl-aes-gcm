#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "thpool.h"
#include "gcm.hpp"

namespace openssl {

    int testEncrypt(char **args) {

        char *pathInFile = args[0];
        char *pathEncFile = args[1];
        char *pathOutFile = args[2];

        printf("%s", pathInFile);
        printf("%s", pathEncFile);
        printf("%s", pathOutFile);

        remove(pathEncFile);
        remove(pathOutFile);

        FILE *in = fopen(pathInFile, "rb");
        FILE *outEnc = fopen(pathEncFile, "wb");

        int inDescriptor = fileno(in);
        int outEncDescriptor = fileno(outEnc);

        unsigned char password[32] = "key";
        unsigned char key[32];
        unsigned char tag[16];
        unsigned char iv[16];
        unsigned char aad[16] = "abcdefghijklmno";

        AESGCM::encryptFile(inDescriptor, outEncDescriptor, password);

        fclose(in);
        fclose(outEnc);

        FILE *inEnc = fopen(pathEncFile, "rb");
        FILE *out = fopen(pathOutFile, "wb");

        int inEncDescriptor = fileno(inEnc);
        int outDescriptor = fileno(out);

        AESGCM::decryptFile(inEncDescriptor, outDescriptor, password);

        fclose(inEnc);
        fclose(out);

        return 0;
    }

    int testEncryptFiles(char **args) {

        char *pathInFile = args[0];
        char *pathEncFile = args[1];
        char *pathOutFile = args[2];

        printf("%s", pathInFile);
        printf("%s", pathEncFile);
        printf("%s", pathOutFile);

        remove(pathEncFile);
        remove(pathOutFile);

        FILE *in = fopen(pathInFile, "rb");
        FILE *outEnc = fopen(pathEncFile, "wb");

        int inDescriptor = fileno(in);
        int outEncDescriptor = fileno(outEnc);

        unsigned char password[32] = "key";

        int inputOutputFileDescriptorTuples[2] = {inDescriptor, outEncDescriptor};

        AESGCM::encryptFiles(inputOutputFileDescriptorTuples, 2, password, 2);

        fclose(in);
        fclose(outEnc);

        FILE *inEnc = fopen(pathEncFile, "rb");
        FILE *out = fopen(pathOutFile, "wb");

        int inEncDescriptor = fileno(inEnc);
        int outDescriptor = fileno(out);

        int inputOutputFileDescriptorTuples2[2] = {inEncDescriptor, outDescriptor};

        AESGCM::decryptFiles(inputOutputFileDescriptorTuples2, 2, password, 2);

        fclose(inEnc);
        fclose(out);

        return 0;
    }

    void function_p(void *argv) {

        testEncrypt((char **) argv);
        int i = 0;
        while (i < 100000000) {
            i++;
        }
    }

    void testThreadPool() {
        threadpool thpool = thpool_init(4);

        char *args[] = {strdup("file.pdf"), strdup("out.pdf.enc"), strdup("out.pdf")};

        thpool_add_work(thpool, function_p, args);

        char *args2[] = {strdup("in.txt"), strdup("out.enc.txt"), strdup("out.txt")};

        thpool_add_work(thpool, function_p, args2);

        char *args3[] = {strdup("file2.pdf"), strdup("out2.pdf.enc"), strdup("out2.pdf")};

        thpool_add_work(thpool, function_p, args3);

        char *args4[] = {strdup("file4.pdf"), strdup("out4.pdf.enc"), strdup("out4.pdf")};

        thpool_add_work(thpool, function_p, args4);

        char *args5[] = {strdup("file5.pdf"), strdup("out5.pdf.enc"), strdup("out5.pdf")};

        thpool_add_work(thpool, function_p, args5);

        thpool_wait(thpool);
        thpool_destroy(thpool);
    }

}

int main(int argc, char **argv) {

    //char *args[] = {  strdup("in.txt"), strdup("out.txt.enc"), strdup("out.txt") };
    char *args[] = {strdup("file.pdf"), strdup("out.pdf.enc"), strdup("out.pdf")};

    //return testEncrypt(args);

    //testThreadPool();
    //return testEncrypt("file.pdf", "out.pdf.enc", "out.pdf");
    //return testEncrypt("in.txt", "out.enc.txt", "out.txt");

    openssl::testEncryptFiles(args);

    return 0;
}