#include "head.h"

/*TODO: add the checks for whether the file exist before executing calling other methods*/

/* A function to encrypt the packet information*/
void encrypt()
{
    FILE* input;
    FILE* output;
    char* buffer;
    long fileLength;

    /* "rb" is read binary mode. */
    input = fopen("temp", "rb");

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
    buffer = (char*)malloc((fileLength)*sizeof( char ));
    fread(buffer, fileLength, 1, input);
    fclose(input);
 
    output = fopen("encrypt", "wb");
    fwrite(buffer, fileLength, 1, output);
    fclose(output);

    free(buffer);
}

