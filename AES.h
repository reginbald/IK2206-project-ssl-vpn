#ifndef __AES_H__
#define __AES_H__

int encrypt(unsigned char *plaintext, int plaintext_len, 
    unsigned char *key, unsigned char *iv, unsigned char *ciphertext);

void decrypt();

#endif