#include "head.h"

/*
*TODO: 
*/

/* Data that is set during the Security Association for decryption */
static const unsigned char key[16] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
static const unsigned char iv[8] = {0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
static const unsigned char salt[4] = {0xca, 0xfe, 0xba, 0xbe};

int decrypt_util(unsigned char *cipher_text, int cipher_text_len, 
unsigned char *plain_text, unsigned char *additional_auth_data, unsigned char *check_buffer);

/* A function to decrypt the packet information*/
void 
decrypt()
{
    FILE* input = NULL;
    FILE* output = NULL;
    FILE* check = NULL;
    char* buffer = NULL;
    long file_length = 0;
    unsigned char* plaintext = NULL;
    unsigned char* additional_auth_data = NULL;
    unsigned char* check_buffer = NULL;
    int ret = 0;

    /* "rb" is read binary mode. */
    input = fopen("output_binary_file", "rb");
    if( input == NULL ){

        printf("Encryption file does not exist error\n");
        goto cleanup;
    }

    /*"input" goes to the end of the file.*/  
    fseek(input, 0, SEEK_END);
  
    /*"file_length" gets the current position of the file pointer which is at the end of the file.*/ 
    file_length = ftell(input);

    /*The length of the payload data is essentially the length of the output removing the ESP as AAD and the IP header.*/
    size_t cipher_text_len = file_length - 36;

    /*Rewind "input" back to the beginning of the file*/
    rewind(input);
    
    /* Here we need a buffer to hold the original plaintext for comparison purposes*/
    check = fopen("input_binary_file", "rb");
    if( check == NULL ){
        printf("Error opening input_binary_file\n");
        goto cleanup;
    }

    check_buffer = (unsigned char*)malloc((cipher_text_len - 16 - 2) * sizeof( char ));
    if( check_buffer == NULL ){
        printf("Error allocating memory for check buffer\n");
        goto cleanup;
    }

    fread(check_buffer, cipher_text_len - 16, 1, check);

    /*Allocate memory to the buffer in order to copy and read from "input"*/
    buffer = (char*)malloc((file_length) * sizeof( char ));

    if( buffer == NULL ){
        printf("Error allocating memory for buffer\n");
        goto cleanup;
    }

    fread(buffer, file_length, 1, input);
 
    output = fopen("decrypt", "wb");
    
    if( output == NULL ){
        printf("Decryption error\n");
        goto cleanup;
    }

    plaintext = (unsigned char*)malloc((2048) * sizeof( char ));

    if ( plaintext == NULL ){
        printf("Error allocating memory for plaintext\n");
        goto cleanup;
    }
    
    unsigned char* cipher_text = (unsigned char*)malloc((cipher_text_len) * sizeof( unsigned char ));

    if( cipher_text == NULL ){
        printf("Error allocating memory for cipher text\n");
        goto cleanup;
    }
    memcpy(cipher_text, buffer + 36, cipher_text_len);

    additional_auth_data = (unsigned char*)malloc(8 * sizeof( unsigned char ));

    if( additional_auth_data == NULL ){
        printf("Error allocating memory for additional authentication data\n");
        goto cleanup;

    }
    memcpy(additional_auth_data, buffer + 20, 8);

    ret = decrypt_util(cipher_text, cipher_text_len, plaintext, additional_auth_data, check_buffer);
    if( ret != 0 ){
        printf("Error decrypting\n");
        goto cleanup;
    }
    
    /*
     *Write the decrypted data to the output file, but in the process we need to reduce the length of what we are writing to the file
     *4 is the length of the next header and the padding length
     *16 is the length of the auth tag
     *20 is the length of the IP header
     *16 is the length of the ESP header and the IV
     */
    fwrite(plaintext, file_length - 4 - 16 - 20 - 16, 1, output);


    cleanup:
    /*Close files, free memory and prevent dangling of pointers*/
        if (input){
            fclose(input);
            input = NULL;
        }
        if (output){
            fclose(output);
            output = NULL;
        }
        if (buffer){
            free(buffer);
            buffer = NULL;
    
        }
        if (plaintext){
            free(plaintext);
            plaintext = NULL;
    
        }
        if (cipher_text){
            free(cipher_text);
            cipher_text = NULL;

        } 
        if( additional_auth_data ){
            free(additional_auth_data);
            additional_auth_data = NULL;

        }
        if ( truncate("encrypt", 0) != 0 ) {
            printf("Error clearing the encrypted file\n");

        } else {
            printf("Encrypted File cleared\n");

        }
    return;
}

int
decrypt_util(unsigned char *cipher_text, int cipher_text_len, 
unsigned char *plain_text, unsigned char *additional_auth_data, unsigned char *check_buffer)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int plaintext_len = 0;
    int ret = 0;

    /* Create and initialise the context */
    if( (ctx = EVP_CIPHER_CTX_new()) == NULL ){
        printf("Error creating context\n");
        goto err;
    }

    /* Initialize decryption operation */
    if( 1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) ){
        printf("Error initializing decryption\n");
        goto err;
    }

    unsigned char nonce[12];
    memcpy(nonce, salt, 4);
    memcpy(nonce + 4, iv, 8);

    /* Specify decryption key and IV */
    if( 1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) ){
        printf("Error setting decryption key and IV\n");
        goto err;
    }

    /* Setting the expected tag value. */
    if( 1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, cipher_text + cipher_text_len - 16) ){
        printf("Error setting expected tag\n");
        goto err;
    }

    /* Add the AAD to the context */
    if( 1 != EVP_DecryptUpdate(ctx, NULL, &len, additional_auth_data, 8) ) {
        printf("Error adding AAD\n");
        goto err;
    }

    /* Decrypt the ciphertext removing the auth tag, the pad length and next header */
    if( 1 != EVP_DecryptUpdate(ctx, plain_text, &len, cipher_text, cipher_text_len - 16) ){
        printf("Error during decryption\n");
        goto err;
    }

    plaintext_len += len;

    /* 
     *Finalize the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plain_text + len, &len);
    
    if( ret == 1 ){
        /* Tag successfully verified */
        plaintext_len += len;
        printf("Decrypted text:\n");
        BIO_dump_fp(stdout, (const char*)plain_text, plaintext_len);

        if (memcmp(plain_text, check_buffer, cipher_text_len - 16 - 2) == 0) {
            printf("Success: Plaintext matches check buffer\n");

        } else {
            printf("Failure: Plaintext does not match check buffer\n");

        }

        printf("Tag successfully verified\n");

    } else{
        /* The verification failed */
        printf("Decryption failed or tag mismatch\n");
        goto err;

    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return 0;

    err:
        /* Error handling and cleanup */
        if( ctx ) 
            EVP_CIPHER_CTX_free(ctx);

        ERR_print_errors_fp(stderr);
        printf("An error occurred\n");
        return 1;
}

// int main()
// {
//     decrypt();

//     return 0;
// }