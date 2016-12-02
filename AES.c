#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

/* Require:
    - Key : 256 bit long
    - IV : 128 bit long
*/
int encrypt(unsigned char *plaintext, int plaintext_len, 
    unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    // Variables
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    //Initialization of the Cipher context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("Init Cipher Context");
        exit(1);
    }

    //Init of encryption cipher
    if (!(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))) {
        perror("Init Encryption Cipher");
        exit(1);
    }

    //Compute the encryption
    if (!(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))) {
        perror("Computation AES");
        exit(1);
    }
    ciphertext_len = len;

    //Finalize the encryption
    if (!(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))) {
        perror("Finalization AES");
        exit(1);
    }
    ciphertext_len += len;

    //Clean Up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

void decrypt() {

}


