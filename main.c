#include<pthread.h>
#include "head.h"

/*TODO: make the synch better,
 *make the encryption and decryption run one after another,
 *add error handling,
 *read from the file, clear it and write as necessary in that order
*/

/*A mutex lock to ensure that only one thread is running at a time.*/
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t enc_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t dec_cond = PTHREAD_COND_INITIALIZER;

/* 1 is used for encryption and 0 for decryption */
static int cond_var=1;


/*
 *The thread used for encryption, calls the encrypt() function included in "head.h".
 *The function waits for the decryption thread to finish before starting.
 *The function signals the decryption thread to start after finishing.
 */
static void*
enc_thread()
{
    pthread_mutex_lock(&mutex);

    while( cond_var != 1 ) 
    {
        pthread_cond_wait(&enc_cond, &mutex);
    }

    encrypt();
    printf("Encrypted\n");
    cond_var=0;

    pthread_cond_signal(&dec_cond);
    pthread_mutex_unlock(&mutex);
}

/*
 *The thread used for encryption, calls the decrypt() function included in "head.h".
 *The function waits for the encryption thread to finish before starting.
 *The function signals the encryption thread to start after finishing.
 */
static void*
dec_thread()
{
    pthread_mutex_lock(&mutex);

    while( cond_var != 0 ) 
    {
        pthread_cond_wait(&dec_cond, &mutex);
    }

    decrypt();
    printf("Decrypted\n");
    cond_var=1;
    
    pthread_mutex_unlock(&mutex);
}

/*Main function call for the application.*/
int main()
{
    create_temp();
    
    pthread_t t1;
    pthread_t t2;

    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&enc_cond, NULL);
    pthread_cond_init(&dec_cond, NULL);

    printf("Start\n");

    pthread_create(&t1, NULL, enc_thread, NULL);
    pthread_create(&t2, NULL, dec_thread, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    pthread_mutex_destroy(&mutex);

    return 0;
}