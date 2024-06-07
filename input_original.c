
#include "head.h"

struct ipsec_test_data pkt_aes_128_gcm = {
	.input_text = {
		.data = {
			/* IP */
			0x45, 0x00, 0x00, 0x3e, 0x69, 0x8f, 0x00, 0x00,
			0x80, 0x11, 0x4d, 0xcc, 0xc0, 0xa8, 0x01, 0x02,
			0xc0, 0xa8, 0x01, 0x01,

			/* UDP */
			0x0a, 0x98, 0x00, 0x35, 0x00, 0x2a, 0x23, 0x43,
			0xb2, 0xd0, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x03, 0x73, 0x69, 0x70,
			0x09, 0x63, 0x79, 0x62, 0x65, 0x72, 0x63, 0x69,
			0x74, 0x79, 0x02, 0x64, 0x6b, 0x00, 0x00, 0x01,
			0x00, 0x01,
		},
		.len = 62,
	},
	.output_text = {
		.data = {
			/* IP - outer header */
			0x45, 0x00, 0x00, 0x74, 0x69, 0x8f, 0x00, 0x00,
			0x80, 0x32, 0x4d, 0x75, 0xc0, 0xa8, 0x01, 0x02,
			0xc0, 0xa8, 0x01, 0x01,

			/* ESP */
			0x00, 0x00, 0xa5, 0xf8, 0x00, 0x00, 0x00, 0x01,

			/* IV */
			0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,

			/* Data */
			0xde, 0xb2, 0x2c, 0xd9, 0xb0, 0x7c, 0x72, 0xc1,
			0x6e, 0x3a, 0x65, 0xbe, 0xeb, 0x8d, 0xf3, 0x04,
			0xa5, 0xa5, 0x89, 0x7d, 0x33, 0xae, 0x53, 0x0f,
			0x1b, 0xa7, 0x6d, 0x5d, 0x11, 0x4d, 0x2a, 0x5c,
			0x3d, 0xe8, 0x18, 0x27, 0xc1, 0x0e, 0x9a, 0x4f,
			0x51, 0x33, 0x0d, 0x0e, 0xec, 0x41, 0x66, 0x42,
			0xcf, 0xbb, 0x85, 0xa5, 0xb4, 0x7e, 0x48, 0xa4,
			0xec, 0x3b, 0x9b, 0xa9, 0x5d, 0x91, 0x8b, 0xd4,
			0x29, 0xc7, 0x37, 0x57, 0x9f, 0xf1, 0x9e, 0x58,
			0xcf, 0xfc, 0x60, 0x7a, 0x3b, 0xce, 0x89, 0x94,

		},
		.len = 116,
	},
};

//create a binary file to use 

int main()
{
	FILE* file= fopen("temp", "wb");

	if(file==NULL)
	{
		printf("error");
		return 1;
	}

	size_t stream=pkt_aes_128_gcm.input_text.len;
	size_t temp=fwrite(pkt_aes_128_gcm.input_text.data, 1, stream,file);

	if(temp!=stream)
	{
		perror("error writing ");
		fclose(file);
		return 1;

	}
	else
	{
		printf("successful");
		fclose(file);
	}

	return 0;

}


