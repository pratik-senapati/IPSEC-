#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

void 
handle_errors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void 
decrypt(unsigned char *cipher_text, int cipher_text_len, unsigned char *key, 
        unsigned char *iv, unsigned char *salt, unsigned char *plain_text)
{
    EVP_CIPHER_CTX *ctx;
    int len=0;
    int plaintext_len=0;
    int ret=0;

    /* Create and initialise the context */
    if( !( ctx = EVP_CIPHER_CTX_new() ) )
        handle_errors();
    
    if( !EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) )
        handle_errors();

    unsigned char nonce[12];
    memcpy(nonce, salt, 4);
    memcpy(nonce + 4, iv, 8);

    if( !EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) )
        handle_errors();
    
    if( !EVP_DecryptUpdate(ctx, plain_text, &len, cipher_text, cipher_text_len) )
        handle_errors();

    printf("Decrypted text:");
    BIO_dump_fp(stdout, (const char*)plain_text, len);


}

int main()
{
    /* Set up the key, iv and tag */
  unsigned char key[16] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
  unsigned char iv[8] = {0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
  unsigned char salt[4] = {0xca, 0xfe, 0xba, 0xbe};

  /* Set up the ciphertext */
  unsigned char ciphertext[64] = {0xde, 0xb2, 0x2c, 0xd9, 0xb0, 0x7c, 0x72, 0xc1,
			0x6e, 0x3a, 0x65, 0xbe, 0xeb, 0x8d, 0xf3, 0x04,
			0xa5, 0xa5, 0x89, 0x7d, 0x33, 0xae, 0x53, 0x0f,
			0x1b, 0xa7, 0x6d, 0x5d, 0x11, 0x4d, 0x2a, 0x5c,
			0x3d, 0xe8, 0x18, 0x27, 0xc1, 0x0e, 0x9a, 0x4f,
			0x51, 0x33, 0x0d, 0x0e, 0xec, 0x41, 0x66, 0x42,
			0xcf, 0xbb, 0x85, 0xa5, 0xb4, 0x7e, 0x48, 0xa4,
			0xec, 0x3b, 0x9b, 0xa9, 0x5d, 0x91, 0x8b, 0xd4,};

  /* Set up the plaintext */
  unsigned char plaintext[62];

  /* Set up the ciphertext length */
  int ciphertext_len = sizeof(ciphertext);

  /* Call the decrypt function */
  decrypt(ciphertext, ciphertext_len, key, iv, salt, plaintext);

//   /* Check if the decryption was successful */
//   if (decryptedtext_len != -1) {
//     /* Success */
//     printf("The plaintext is: %s\n", plaintext);
//   } else {
//     /* The verify failed */
//     printf("The decryption failed\n");
//   }

  return 0;

}
