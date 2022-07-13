#include "hexende.h"
#include <stdio.h>

int dataToHex(char* inData, int input_len, char* outHex, int* out_len){
	
	
	if(inData == NULL) return DATA_ERR;

	int i = 0;
	
	for(; i <= input_len - 1; i++){

		sprintf(outHex+2*i, "%02x",(unsigned char)*(inData+i));
		
	}
	
	*out_len = strlen(outHex);

	return CONVERT_OK;
}

int hexchrTobin(const char hex, char *out){
	
	if (out == NULL)
		return 0;

	if (hex >= '0' && hex <= '9') {
		*out = hex - '0';
	}
	else if (hex >= 'A' && hex <= 'F') {
		*out = hex - 'A' + 10;
	}
	else if (hex >= 'a' && hex <= 'f') {
		*out = hex - 'a' + 10;
	}
	else {
		return -1;
	}

}

int hexToData(const char *InHex,int input_len, unsigned char *outData, int* out_len){

	char b1;
	char b2;
	
	int i = 0;

	for(i = 0; i < input_len - 1; i++){

		if(!(InHex[i] >= 48 && InHex[i] <= 57)){
			if(!(InHex[i] >= 65 && InHex[i] <= 70)){
				if(!(InHex[i] >= 97 && InHex[i] <= 102)){
					return DATA_ERR;
				}
			}
		}
	}	

	if(InHex == NULL) return -1;
	if(input_len % 2 != 0) return -1;
		
	*out_len = input_len /= 2;
	
	for (i = 0; i < *out_len; i++) {
	
		if (!hexchrTobin(InHex[i * 2], &b1) || !hexchrTobin(InHex[i * 2 + 1], &b2)) {
			return -1;
		}
						
		*(outData + i) = (b1 << 4) | b2;
						
	}
	
	return CONVERT_OK;
}


