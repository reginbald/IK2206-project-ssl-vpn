#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>

int main() {
    // Secret key
    char key[] = "012345678";

    // Encrypted data to be hashed using HMAC
    char data[] = "hello world";

    unsigned char* hmac;

    hmac = HMAC(EVP_sha256(), key, strlen(key), (unsigned char*)data, strlen(data), NULL, NULL);

    char mdString[32];
    for(int i = 0; i < 32; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)hmac[i]);
 
    printf("HMAC: %s\n", mdString);
 
    return 0;
}
