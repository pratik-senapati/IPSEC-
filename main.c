#include<pthread.h>
#include "head.h"

/*TODO: make the synch better,
 *make the encryption and decryption run one after another,
 *add error handling,
 *read from the file, clear it and write as necessary in that order
 *check the return values of functions
 *add input_original.c here as well
*/

/*A mutex lock to ensure that only one thread is running at a time.*/
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int temp_created=0;

/*The thread used for encryption, calls the encrypt() function included in "head.h".*/
static void*
enc_thread()
{
    pthread_mutex_lock(&mutex);

    encrypt();
    printf("Encrypted\n");

    pthread_mutex_unlock(&mutex);
}

/*The thread used for encryption, calls the decrypt() function included in "head.h".*/
static void*
dec_thread()
{
    pthread_mutex_lock(&mutex);

    decrypt();
    printf("Decrypted\n");
    
    pthread_mutex_unlock(&mutex);
}

/*Main function call for the application.*/
int main()
{
    create_temp();
    sleep(2);
    pthread_t t1;
    pthread_t t2;

    pthread_mutex_init(&mutex, NULL);

    printf("Start");

    pthread_create(&t1, NULL, enc_thread, NULL);
    pthread_create(&t2, NULL, dec_thread, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    pthread_mutex_destroy(&mutex);

    return 0;
}