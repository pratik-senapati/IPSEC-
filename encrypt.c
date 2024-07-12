#include "head.h"

/*
*TODO: 
*Add better comments and spacing
*/

/* Data that is set during the Security Association for encryption */
static const unsigned char key[16] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
static const unsigned char iv[8] = {0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
static const unsigned char salt[4] = {0xca, 0xfe, 0xba, 0xbe};
static const unsigned char esp[8] = {0x00, 0x00, 0xa5, 0xf8, 0x00, 0x00, 0x00, 0x01};
static const unsigned char ip[20] = {0x45, 0x00, 0x00, 0x74, 0x69, 0x8f, 0x00, 0x00, 0x80, 0x32, 0x4d, 0x75, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x01,};

int encrypt_util(unsigned char *plaintext, size_t *plaintext_len, unsigned char *ciphertext, size_t *cipher_text_len);

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
    int ret = 0;

    /* "rb" is read binary mode. */
    input = fopen("input_binary_file", "rb");

    if( input == NULL )
    {
        printf("temp file does not exist error\n");
        goto cleanup;
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
    output = fopen("encrypt", "wb");

    if( output == NULL ){
        printf("Encryption error\n");
        goto cleanup;
    }

    ciphertext= (unsigned char*)malloc((2048) * sizeof( char ));
    if ( ciphertext == NULL ){
        printf("Error allocating memory for ciphertext\n");
        goto cleanup;
    }
    

    unsigned char* plain_text = (unsigned char*)malloc((plain_text_len) * sizeof( unsigned char ));
    if( !plain_text ){
        printf("Error allocating memory for plain text\n");
        return;
    }
    memcpy(plain_text, buffer, plain_text_len);

    ret = encrypt_util(plain_text, &plain_text_len, ciphertext, &cipher_text_len);
    if( ret != 0 ){
        printf("Error in encryption\n");
        goto cleanup;
    }

    fwrite(ciphertext, cipher_text_len, 1, output);

    if (ferror(output)) {
        printf("Error writing to output file\n");
        goto cleanup;
    }

    printf("Encrypted text:\n");
    BIO_dump_fp(stdout, (const char*)ciphertext, cipher_text_len);
    
    /* Cleanup sequence to close all the files and free all the memory */
    cleanup:
        if ( output ) {
            fclose(output);
            output = NULL;

        }
        if ( buffer ) {
            free(buffer);
            buffer = NULL;

        }
        if ( plain_text ) {
            free(plain_text);
            plain_text = NULL;

        }
        if ( ciphertext ) {
            free(ciphertext);
            ciphertext = NULL;

        }

        if ( truncate("decrypt", 0) != 0 )
            printf("Error clearing the decrypted file\n");
        else
            printf("Decrypted File cleared\n");
        
    return;
}

int
encrypt_util(unsigned char *plaintext, size_t *plaintext_len, unsigned char *ciphertext, size_t *cipher_text_len)
{
    EVP_CIPHER_CTX* ctx;
    int len = 0;
    int block_size = 16;
    int padding_len = block_size - ((*plaintext_len + 2) % block_size);
    if(padding_len == block_size){
        padding_len = 0;
    }

    /* New plaintext length including padding, padding length, and next header fields, +2 for padding length and next header */
    size_t new_plaintext_len = *plaintext_len + padding_len + 2; 
    unsigned char padded_plaintext[new_plaintext_len];

    memcpy(padded_plaintext, plaintext, *plaintext_len);

    for(int i = 0; i < padding_len; i++){
        padded_plaintext[*plaintext_len + i] = (unsigned char)(i + 1);
    }

    padded_plaintext[new_plaintext_len - 2] = (unsigned char)padding_len;

    /* Add next header field (Here it is 4 indicating it is IPv4 communication) */
    padded_plaintext[new_plaintext_len - 1] = 4;

    *plaintext_len = new_plaintext_len;

    /* Create and initialise the context */
     if( ( ctx = EVP_CIPHER_CTX_new() ) == NULL ){
        printf("Error in EVP_CIPHER_CTX_new\n");
        goto err;
    }

    /* Creating the nonce from the IV and the Salt */
    unsigned char nonce[12];
    memcpy(nonce, salt, 4);
    memcpy(nonce + 4, iv, 8);        

    /* Initialise the encryption operation */
    if( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, nonce) ) {
        printf("Error in EVP_EncryptInit_ex\n");
        goto err;
    }

    /* Add the AAD */
    if( 1 != EVP_EncryptUpdate(ctx, NULL, &len, esp, sizeof(esp)) ) {
        printf("Error adding AAD\n");
        goto err;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output */
    if( 1 != EVP_EncryptUpdate(ctx, ciphertext, &len, padded_plaintext, *plaintext_len) ){
        printf("Error in EVP_EncryptUpdate\n");
        goto err;
    }

    *cipher_text_len += len;

    /* Finalise the encryption */
    if( 1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) ){
        printf("Error in EVP_EncryptFinal_ex\n");
        goto err;
    }

    *cipher_text_len += len;

    unsigned char tag[16];

    if( 1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) ){
        printf("Error in EVP_CIPHER_CTX_ctrl\n");
        goto err;
    }

    /* Append the tag to the end, and IP Header, ESP Header and IV in that order */
    memcpy(ciphertext + *cipher_text_len, tag, 16);
    *cipher_text_len += 16;

    /* Make space for the IP header, ESP Header and IV , (20 + 8 + 8)*/
    memmove(ciphertext + 36, ciphertext, *cipher_text_len);
    memcpy(ciphertext , ip, 20);
    memcpy(ciphertext + 20, esp, 8);
    memcpy(ciphertext + 28, iv, 8);

    *cipher_text_len += 20 + 8 + 8 ;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return 0;

    err:
        /* Error handling and cleanup in case of failure*/
        if(ctx) 
            EVP_CIPHER_CTX_free(ctx);

        ERR_print_errors_fp(stderr);
        printf("An error occurred\n");
        return 1;
}

// int main()
// {
//     encrypt();

//     return 0;
// }