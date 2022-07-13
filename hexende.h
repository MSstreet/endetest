#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define		DATA_ERR	10000

#define		CONVERT_OK	1

int dataToHex(char* inData, int input_len, char* outHex,int* out_len);
int hexToData(const char *Inhex,int input_len, unsigned char *outData, int* out_len);
int hexchrTobin(const char hex, char *out);
 
