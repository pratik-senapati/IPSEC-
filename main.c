#include<pthread.h>

#include "head.h"

/*
 *TODO: 
 *Add robust error handling, in the case one of the threads waits too long it'll finish executing (timeout) 
 *Add error handling in mutex lock checking 
 *Error handling in whether the thread is created or not 
 *Add exit signal handling 
*/

static void *enc_thread();
static void *dec_thread();
static void handle_signal();

/*A mutex lock to ensure that only one thread is running at a time.*/
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/*Condition variables to signal the threads to start.*/
static pthread_cond_t enc_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t dec_cond = PTHREAD_COND_INITIALIZER;

static pthread_cond_t termination_cond = PTHREAD_COND_INITIALIZER;

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
    pthread_cond_init(&termination_cond, NULL);

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
 */
static void*
enc_thread()
{
    // printf("stuck check 20 \n");
    while( 1 )
    {
        // printf("stuck check 0 \n");
        pthread_mutex_lock(&mutex);

        if( terminate_threads == 1 ){

                // printf("stuck check 26 \n");
                // pthread_cond_wait(&termination_cond, &mutex);
                // printf("stuck check 23");
                break;
        }

        // printf("stuck check 30 \n");
        
        while( cond_var != 1 ) 
        {
            // printf("Stuck check 9\n");
            pthread_cond_wait(&enc_cond, &mutex);
            // printf("Stuck check 90\n");
            pthread_mutex_unlock(&mutex);
        }

        // printf("stuck check 31 \n");

       if( terminate_threads != 1 && enc_counter == dec_counter){

            // printf("stuck check 35 \n");
            enc_counter++;
            fflush(stdout);
            encrypt();
            // printf("stuck check 32 \n");
            printf("Encrypted:%d\n", enc_counter-1);
            cond_var=0;

        } else{
            break;
        }

        pthread_cond_signal(&dec_cond);
        pthread_mutex_unlock(&mutex);
        
    }

    // printf("stuck check 6 \n");
    pthread_cond_signal( &dec_cond );
    // cond_var=0;
    // printf("stuck check 8 \n");
    printf("\nSignal caught\n");
    printf("Exiting encryption thread...\n");
    pthread_exit(NULL);
    
}

/*
 *The thread used for encryption, calls the decrypt() function included in "head.h".
 *The function waits for the encryption thread to finish before starting.
 *The function signals the encryption thread to start after finishing.
 */
static void*
dec_thread()
{
    
    while( 1 )
    {
        // printf("stuck check 3 \n");
        pthread_mutex_lock(&mutex);

        // if( terminate_threads == 1 ){
               
        //        printf("stuck check 50 \n");
        //        pthread_cond_signal(&termination_cond);
        //        break;
        // }

        while( cond_var != 0 ) 
        {
            // printf("stuck check 4 \n");
            if( terminate_threads == 1 ){
               
               if( enc_counter == dec_counter + 1 )
               {
                decrypt();
                printf("Decrypted:%d\n", dec_counter);
                cond_var=1;
                dec_counter++;

                //last change 
               }
            //    printf("stuck check 10 \n");
               pthread_cond_signal(&termination_cond);
               break;
        }
            pthread_cond_wait(&dec_cond, &mutex);
        }

        if( dec_counter == enc_counter - 1 ){

            decrypt();
            printf("Decrypted:%d\n", dec_counter);
            cond_var=1;
            dec_counter++;

        } else{
            break;
        }

        if( terminate_threads == 1 ){
               
            //    printf("stuck check 50 \n");
               pthread_cond_signal(&termination_cond);
               break;
        }

        pthread_cond_signal(&enc_cond);

        pthread_mutex_unlock(&mutex);

        // printf("stuck check 5 \n");
        
    }

    pthread_mutex_unlock(&mutex);
    printf("\nSignal caught\n");
    printf("Exiting decryption thread...\n");
    pthread_exit(NULL);
    
}

void 
handle_signal()
{
    /* When it gets the interrupt the signal, obtain the lock and wake both the threads up */
    pthread_mutex_lock(&mutex);
    printf("Signal locked\n");
    terminate_threads = 1;
    pthread_cond_signal(&enc_cond);
    pthread_cond_signal(&dec_cond);
    pthread_mutex_unlock(&mutex);
    
}
