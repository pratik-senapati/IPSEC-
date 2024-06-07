#include "head.h"
#include<pthread.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void* enc_thread()
{
    pthread_mutex_lock(&mutex);
    encrypt();
    printf("Encrypted\n");
    pthread_mutex_unlock(&mutex);
}

void* dec_thread()
{
    pthread_mutex_lock(&mutex);
    decrypt();
    printf("Decrypted\n");
    pthread_mutex_unlock(&mutex);
}

int main()
{
    pthread_t t1;
    pthread_t t2;

    pthread_mutex_init(&mutex, NULL);

    printf("Start");

    pthread_create(&t1, NULL, enc_thread, NULL);
    pthread_create(&t2, NULL, dec_thread, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    pthread_mutex_destroy(&mutex);


    return 2;
}