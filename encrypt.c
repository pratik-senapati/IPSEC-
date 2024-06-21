#include "head.h"

/*
*TODO: 
*/

/* A function to encrypt the packet information*/
void encrypt()
{
    FILE* input = NULL;
    FILE* output = NULL;
    char* buffer = NULL;
    long fileLength = 0;

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
     *"filelength" gets the current position of the file pointer 
     *which is at the end of the file.
    
    */ 
    fileLength = ftell(input);

    /*Rewind "input" back to the beginning of the file*/
    rewind(input);

    /*Allocate memory to the buffer in order to copy and read from "input".*/
    buffer = (char*)malloc((fileLength) * sizeof( char ));
    fread(buffer, fileLength, 1, input);
    fclose(input);
 
    output = fopen("encrypt", "wb");

    if( output == NULL )
    {
        printf("Encryption error\n");
        return;
    }

    fwrite(buffer, fileLength, 1, output);
    fclose(output);

    free(buffer);

    /* Clear the "decrypt" file */
     if( truncate("decrypt", 0) != 0 ){ 

        printf("Error clearing the decrytped file\n");

    }else {

        printf("Decrypted File cleared\n");

    }
    
    return;
}

