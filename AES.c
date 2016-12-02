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

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext) {
	EVP_CIPHER_CTX *ctx;

	int len;
	int plaintext_len;

	/* Create and initialise the context */
  	if(!(ctx = EVP_CIPHER_CTX_new())) 
  	{
  		perror("INIT error");
  		exit(1);
  	}

  	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) 
	{
  		perror("DecryptINIT error");
  		exit(1);
	}

   	/* Provide the message to be decrypted, and obtain the plaintext output.
   	* EVP_DecryptUpdate can be called multiple times if necessary
   	*/
  	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
  		perror("DecryptUPDATE error");
  		exit(1);
    }

	plaintext_len = len;

   	/* Finalise the decryption. Further plaintext bytes may be written at
   	* this stage.
   	*/
  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
  	{
  		perror("DecryptFINAL error");
  		exit(1);
  	}

  	plaintext_len += len;

  	/* Clean up */
  	EVP_CIPHER_CTX_free(ctx);

  	return plaintext_len;

}


