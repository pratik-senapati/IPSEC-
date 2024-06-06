#include "head.h"


void encrypt()
{
    FILE* input;
    FILE* output;

    char* buffer;
    long fileLength;


    input=fopen("temp", "rb");
    //open the file in read binary mode

    if(!input)
    {
        printf("error");
        return;
    }

    printf("success");

    fseek(input, 0, SEEK_END);
    //this goes to end of the file

    fileLength=ftell(input);
    //this gets the current position of the file pointer

    //go back to the beginning of the file 
    rewind(input);

    //now allocate memory to the buffer in order to copy
    buffer= (char*)malloc((fileLength)*sizeof(char));
    fread(buffer, fileLength, 1, input);
    fclose(input);


    //now open the output file and write 
    output=fopen("encrypt", "wb");
    fwrite(buffer, fileLength, 1, output);
    fclose(output);

    free(buffer);


}

// int main()
// {
//     encrypt();
//     return 0;
// }