#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>

unsigned char* generate_hmac(unsigned char *key, unsigned char *data) {
    unsigned char* hmac;
    hmac = HMAC(EVP_sha256(), key, strlen((const char *)key), data, strlen((const char *)data), NULL, NULL);
    return hmac;
}

int main() {
    // Secret key
    char key[] = "012345678";

    // Encrypted data to be hashed using HMAC
    char data[] = "hello world";

    unsigned char* hmac;

    hmac = generate_hmac((unsigned char *)key, (unsigned char *)data);

    char mdString[32];
    for(int i = 0; i < 32; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)hmac[i]);
 
    printf("HMAC: %s\n", mdString);
 
    return 0;
}

