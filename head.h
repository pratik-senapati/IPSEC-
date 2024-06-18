#ifndef HEAD_H
#define HEAD_H

#include<stdint.h>
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>

#define IPSEC_TEXT_MAX_LEN 16384u

void encrypt();
void decrypt();
int create_temp();

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
};

#endif /*HEAD_H*/