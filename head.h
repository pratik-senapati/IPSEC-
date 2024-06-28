#ifndef HEAD_H
#define HEAD_H

#include<stdint.h>
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<signal.h>
#include<string.h>

#include <openssl/evp.h>
#include<openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>


#define IPSEC_TEXT_MAX_LEN 16384u

void encrypt();
void decrypt();
int create_temp_input();
int create_temp_output();

/*Basic struct definition from dpdk docs for ipsec test vectors*/
struct ipsec_test_data {
   struct  {
		uint8_t      data[IPSEC_TEXT_MAX_LEN];
		unsigned int len;
	}input_text;

	struct  {
		uint8_t      data[IPSEC_TEXT_MAX_LEN];
		unsigned int len;
	}output_text;

	struct {
		uint8_t data[4];
		unsigned int len;
	} salt;

	struct {
		uint8_t data[32];
	} key;

	struct {
		uint8_t data[16];
	} iv;
};

#endif /*HEAD_H*/