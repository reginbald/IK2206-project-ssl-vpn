void encrypt(char *plaintext, int plaintext_len, char *iv, 
    char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext);