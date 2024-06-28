#include "head.h"

/*
*TODO: 
*Add authentication tag verification 
*/

static const unsigned char key[16] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
static const unsigned char iv[8] = {0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
static const unsigned char salt[4] = {0xca, 0xfe, 0xba, 0xbe};

void decrypt_util(unsigned char *cipher_text, int cipher_text_len, unsigned char *plain_text);

void handle_errors();

/* A function to decrypt the packet information*/
void 
decrypt()
{
    FILE* input = NULL;
    FILE* output = NULL;
    char* buffer = NULL;
    long file_length = 0;
    unsigned char* plaintext = NULL;

    /* "rb" is read binary mode. */
    input = fopen("output_binary_file", "rb");

    if( input == NULL ){

        printf("Encryption file does not exist error\n");
        return;
    }
    /*"input" goes to the end of the file.*/  
    fseek(input, 0, SEEK_END);
  
    /*
     *"file_length" gets the current position of the file pointer 
     *which is at the end of the file.
    
    */ 
    file_length = ftell(input);

    /* The length of the payload data is essentially the length of the output, removing the IP header, ESP and Auth Tag. */
    size_t cipher_text_len = file_length - 36 - 16;

    /*Rewind "input" back to the beginning of the file*/
    rewind(input);

    /*Allocate memory to the buffer in order to copy and read from "input"*/
    buffer = (char*)malloc((file_length) * sizeof( char ));
    fread(buffer, file_length, 1, input);
    fclose(input);
 
    output = fopen("decrypt", "wb");

    if( output == NULL ){
        printf("Decryption error\n");
        return;
    }

    plaintext = (char*)malloc((2048) * sizeof( char ));

    unsigned char* cipher_text = (unsigned char*)malloc((cipher_text_len) * sizeof( unsigned char ));

    if( !cipher_text ){
        printf("Error allocating memory for cipher text\n");
        return;
    }

    memcpy(cipher_text, buffer + 36, cipher_text_len);

    decrypt_util(cipher_text, cipher_text_len, plaintext);
    
    fwrite(plaintext, file_length, 1, output);
    fclose(output);

    free(buffer);

    free(plaintext);

    free(cipher_text);

    /* Clear the "encrypt" file */
    if( truncate("encrypt", 0) != 0 ){ 

        printf("Error clearing the encrypted file\n");

    }else {

        printf("Encrypted File cleared\n");

    }

    return;
}

void 
decrypt_util(unsigned char *cipher_text, int cipher_text_len, unsigned char *plain_text)
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

void 
handle_errors()
{
    ERR_print_errors_fp(stderr);
    exit(0);
}

int main()
{
    decrypt();

    return 0;
}