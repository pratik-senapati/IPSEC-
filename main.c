#include<pthread.h>

#include "head.h"

static void *enc_thread();
static void *dec_thread();
static void handle_signal();

/*A mutex lock to ensure that only one thread is running at a time.*/
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/*Condition variables to signal the threads to start.*/
static pthread_cond_t enc_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t dec_cond = PTHREAD_COND_INITIALIZER;

// static pthread_cond_t termination_cond = PTHREAD_COND_INITIALIZER;

/* 1 is used for encryption and 0 for decryption */
static int cond_var=1;

/*A flag to terminate the threads.*/
static volatile int terminate_threads=0;

static int enc_counter=0;
static int dec_counter=0;

/*Main function call for the application.*/
int main()
{
    create_temp_input();
    create_temp_output();
    
    pthread_t t1;
    pthread_t t2;

    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&enc_cond, NULL);
    pthread_cond_init(&dec_cond, NULL);
    
    signal(SIGINT, handle_signal);

    printf("Start\n");

    pthread_create(&t1, NULL, enc_thread, NULL);
    pthread_create(&t2, NULL, dec_thread, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    pthread_mutex_destroy(&mutex);

    return 0;
}

/*
 *The thread used for encryption, calls the encrypt() function included in "head.h".
 *The function waits for the decryption thread to finish before starting.
 *The function signals the decryption thread to start after finishing.
 *The function is gracefully terminated when the signal is caught, and the termination happens after a cycle is finished.
 *A cycle being the process in which the encryption function is called, followed by the decryption function.
 */
static void*
enc_thread()
{
    int ret = -1;

    while( 1 )
    {
        ret = pthread_mutex_lock(&mutex);
        if( ret != 0 ){

            printf("Error in obtaining the lock\n");
            fflush(stdout);
            terminate_threads = 1;
        }

        if( terminate_threads == 1 )
            break;
    
        while( cond_var != 1 ) 
        {
            ret = pthread_cond_wait(&enc_cond, &mutex);
            if ( ret != 0 ){

                printf("Error in waiting for the condition\n");
                terminate_threads = 1;
            }
            pthread_mutex_unlock(&mutex);
        }

       if( terminate_threads != 1 && enc_counter == dec_counter ){

            enc_counter++;
            encrypt();
            printf("Encrypted:%d\n", enc_counter-1);
            cond_var=0;

        } else
            break;

        ret = pthread_cond_signal(&dec_cond);
        if( ret != 0 ){
            printf("Error in signalling the decryption thread\n");
            terminate_threads = 1;
        }

        pthread_mutex_unlock(&mutex);
        
    }

    pthread_cond_signal( &dec_cond );
    printf("\nSignal caught\n");
    printf("Exiting encryption thread...\n");
    pthread_exit(NULL);
    
}

/*
 *The thread used for decryption, calls the decrypt() function included in "head.h".
 *The function waits for the encryption thread to finish before starting.
 *The function signals the encryption thread to start after finishing.
 *The function is gracefully terminated when the signal is caught, and the termination happens after a cycle is finished.
 */
static void*
dec_thread()
{
    int ret = -1;   
    while( 1 )
    {
        ret = pthread_mutex_lock(&mutex);

        if( ret != 0 ){
            printf("Error in obtaining the lock\n");
            fflush(stdout);
            terminate_threads = 1;
        }

        while( cond_var != 0 ) 
        {
                if( terminate_threads == 1 ){
                
                if( enc_counter == dec_counter + 1 ){
                    
                    decrypt();
                    printf("Decrypted:%d\n", dec_counter);
                    fflush(stdout);
                    cond_var=1;
                    dec_counter++;

                }
                break;
            }
                ret = pthread_cond_wait(&dec_cond, &mutex);
                if ( ret != 0 )
                {
                    printf("Error in waiting for the condition\n");
                    fflush(stdout);
                    terminate_threads = 1;
                }
        }

        if( dec_counter == enc_counter - 1 ){

            decrypt();
            printf("Decrypted:%d\n", dec_counter);
            fflush(stdout);
            cond_var=1;
            dec_counter++;

        } else
            break;
        
        ret = pthread_cond_signal(&enc_cond);
        if( ret != 0 ){
            printf("Error in signalling the encryption thread\n");
            fflush(stdout);
            terminate_threads = 1;
        }

        ret = pthread_mutex_unlock(&mutex);
        if( ret != 0 ){
            printf("Error in unlocking the mutex\n");
            fflush(stdout);
            terminate_threads = 1;
        }
   
    }

    pthread_mutex_unlock(&mutex);
    printf("\nSignal caught\n");
    fflush(stdout);
    printf("Exiting decryption thread...\n");
    fflush(stdout);
    pthread_exit(NULL);
    
}

void 
handle_signal()
{
    /* When it gets the interrupt signal, obtain the lock and wake both the threads up */
    int lock_result = pthread_mutex_lock(&mutex);
    int unlock_result = 0;

    /* Error checking for getting the lock */
    if( lock_result != 0 ){
        printf("Error in obtaining the lock\n");
        printf("Exiting...\n");
        terminate_threads=1;
    
    } else {
        write(STDOUT_FILENO, "Signal caught\n", 15);
        terminate_threads = 1;
        pthread_cond_signal(&enc_cond);
        pthread_cond_signal(&dec_cond);

        unlock_result = pthread_mutex_unlock(&mutex);

        if( unlock_result != 0 ){
            printf("Error in unlocking the mutex\n");
            printf("Exiting...\n");
            terminate_threads=1;
        }
    
    }
}
