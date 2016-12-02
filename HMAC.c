#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>

unsigned char* generate_hmac(unsigned char *key, unsigned char *data) {
    unsigned char* hmac;
    hmac = HMAC(EVP_sha256(), key, strlen((const char *)key), data, strlen((const char *)data), NULL, NULL);
    return hmac;
}

int compare_hmac(unsigned char *key, unsigned char *data, unsigned char *hmac) {
    unsigned char* new_hmac;
    new_hmac = generate_hmac(key, data);

    for(int i = 0; i < 32; i++) {
        if (hmac[i] != new_hmac[i]){
            return 0;
        }
    }

    return 1;
}

int main() {
    // Secret key
    char key[] = "012345678";
    
    // Encrypted data to be hashed using HMAC
    char data[] = "hello world";

    unsigned char *hmac = (unsigned char*)malloc(sizeof(char) * 32);
    unsigned char *old_hmac = (unsigned char*)malloc(sizeof(char) * 32);

    hmac = generate_hmac((unsigned char *)key, (unsigned char *)data);

    //char mdString[32];
    //for(int i = 0; i < 32; i++)
    //     sprintf(&mdString[i*2], "%02x", (unsigned int)hmac[i]);
    //printf("HMAC: %s\n", mdString);

    // Compare HMAC
    memcpy(old_hmac, hmac, 32);
    char fkey[] = "000000000";
    char fdata[] = "world hello";

    if(compare_hmac((unsigned char *)key, (unsigned char *)data, old_hmac)){
        printf("CORRECT \n");
    } else {
        printf("WRONG\n");
    }

    if(compare_hmac((unsigned char *)fkey, (unsigned char *)data, old_hmac)){
        printf("WRONG\n");
    } else {
        printf("CORRECT\n");
    }

    if(compare_hmac((unsigned char *)key, (unsigned char *)fdata, old_hmac)){
        printf("WRONG\n");
    } else {
        printf("CORRECT\n");
    }

    if(compare_hmac((unsigned char *)fkey, (unsigned char *)fdata, old_hmac)){
        printf("WRONG\n");
    } else {
        printf("CORRECT\n");
    }
    return 0;
}

