#include "head.h"


int main()
{
    printf("Start\n");
    // fflush(stdout);
    encrypt();

    sleep(2);
    printf("Encrypted\n");

    decrypt();
    printf("Decrypted\n");


    return 2;
}