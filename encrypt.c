#include "head.h"

/*
*TODO: 
*Add AAD handling for tag
*Attach tag, IV, ESP and IP header to the output in the correct order
*Add better error handling
*/

static const unsigned char key[16] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
static const unsigned char iv[8] = {0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
static const unsigned char salt[4] = {0xca, 0xfe, 0xba, 0xbe};
static const unsigned char esp[8] = {0x00, 0x00, 0xa5, 0xf8, 0x00, 0x00, 0x00, 0x01};

void encrypt_util(unsigned char *plaintext, size_t *plaintext_len, unsigned char *ciphertext, size_t *cipher_text_len);

void handle_errors();

/* A function to encrypt the packet information*/
void 
encrypt()
{
    FILE* input = NULL;
    FILE* output = NULL;
    char* buffer = NULL;
    long file_length = 0;
    unsigned char* ciphertext = NULL;
    size_t cipher_text_len = 0;

    /* "rb" is read binary mode. */
    input = fopen("input_binary_file", "rb");

    if( input == NULL )
    {
        printf("temp file does not exist error\n");
        return;
    }
    
    /*"input" goes to the end of the file.*/  
    fseek(input, 0, SEEK_END);
  
    /*
     *"file_length" gets the current position of the file pointer 
     *which is at the end of the file.
    
    */ 
    file_length = ftell(input);

    /* The length of the payload data is essentially the length of the output, removing the IP header.*/
    size_t plain_text_len = file_length;

    /*Rewind "input" back to the beginning of the file*/
    rewind(input);

    /*Allocate memory to the buffer in order to copy and read from "input".*/
    buffer = (char*)malloc((file_length) * sizeof( char ));
    fread(buffer, file_length, 1, input);
    fclose(input);
 
    output = fopen("encrypt", "wb");

    if( output == NULL )
    {
        printf("Encryption error\n");
        return;
    }

    ciphertext= (char*)malloc((2048) * sizeof( char ));

    unsigned char* plain_text = (unsigned char*)malloc((plain_text_len) * sizeof( unsigned char ));

    if( !plain_text ){
        printf("Error allocating memory for plain text\n");
        return;
    }

    memcpy(plain_text, buffer, plain_text_len);

    encrypt_util(plain_text, &plain_text_len, ciphertext, &cipher_text_len);

    fwrite(ciphertext, cipher_text_len, 1, output);
    if (ferror(output)) {
        printf("Error writing to output file\n");
        return;
    }
    
    fclose(output);

    free(buffer);

    free(plain_text);

    free(ciphertext);

    /* Clear the "decrypt" file */
     if( truncate("decrypt", 0) != 0 ){ 

        printf("Error clearing the decrypted file\n");

    }else {

        printf("Decrypted File cleared\n");

    }
    
    return;
}

void
encrypt_util(unsigned char *plaintext, size_t *plaintext_len, unsigned char *ciphertext, size_t *cipher_text_len)
{
    EVP_CIPHER_CTX* ctx;
    int len = 0;
    int block_size = 16;
    int padding_len = block_size - ((*plaintext_len + 2) % block_size);
    if(padding_len == block_size){
        padding_len = 0;
    } 

    // New plaintext length including padding, padding length, and next header fields
    size_t new_plaintext_len = *plaintext_len + padding_len + 2; // +2 for padding length and next header
    unsigned char padded_plaintext[new_plaintext_len];

    memcpy(padded_plaintext, plaintext, *plaintext_len);

    for(int i = 0; i < padding_len; i++){
        padded_plaintext[*plaintext_len + i] = (unsigned char)(i + 1);
    }

    padded_plaintext[new_plaintext_len - 2] = (unsigned char)padding_len;

    // Add next header field (example: assuming TCP, which is 6)
    padded_plaintext[new_plaintext_len - 1] = 4;

    *plaintext_len = new_plaintext_len;

    /* Create and initialise the context */
     if( ( ctx = EVP_CIPHER_CTX_new() ) == NULL ){
        printf("Error in EVP_CIPHER_CTX_new\n");
        handle_errors();
    }

    unsigned char nonce[12];
    memcpy(nonce, salt, 4);
    memcpy(nonce + 4, iv, 8);        

    /* Initialise the encryption operation */
    if( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, nonce) ) {
        printf("Error in EVP_EncryptInit_ex\n");
        handle_errors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output */
    if( 1 != EVP_EncryptUpdate(ctx, ciphertext, &len, padded_plaintext, *plaintext_len) ){
        printf("Error in EVP_EncryptUpdate\n");
        handle_errors();
    }

    *cipher_text_len += len;

    /* Finalise the encryption */
    if( 1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) ){
        printf("Error in EVP_EncryptFinal_ex\n");
        handle_errors();
    }

    *cipher_text_len += len;

    unsigned char tag[16];

    if( 1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) ){
        printf("Error in EVP_CIPHER_CTX_ctrl\n");
        handle_errors();
    }

    memcpy(ciphertext + *cipher_text_len, tag, 16);

    *cipher_text_len += 16;

    printf("Ciphertext is: %s\n", ciphertext);

    printf("Cipher text length is: %ld\n", *cipher_text_len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return;
}

void 
handle_errors()
{
    ERR_print_errors_fp(stderr);
    printf("errors\n");
    exit(0);
}

int main()
{
    encrypt();

    return 0;
}