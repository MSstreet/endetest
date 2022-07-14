#include <stdio.h>
#include "ende.h"
#include "hexende.h"

int main(int argc, char* argv[]){
	
	EDGE_CIPHER_PARAMETERS param1; 
	test_param param;	
	
	uint32_t cipherId = EDGE_CIPHER_ID_SEED128; 
	
	uint8_t key[BLOCKSIZE] = { 0x00, };
	uint32_t keyLen = BLOCKSIZE;
	
	uint8_t* plain = "start1234567890123456end";
	uint32_t plainLen = strlen(plain);
	
	uint8_t* out = NULL;
	out = (uint8_t*)malloc(sizeof(uint8_t) * plainLen + 16);
	uint32_t outLen = 0;

	uint8_t* out1 = NULL;
	out1 = (uint8_t*)malloc(sizeof(uint8_t) * plainLen + 16);
	uint32_t outLen1 = 0;

	uint8_t* outHex = NULL;
	outHex = (uint8_t*)malloc((sizeof(uint8_t) * plainLen + 16) * 2 + 1);
	uint32_t outHexLen = 0;
	
	uint8_t* dec = NULL;
	dec = (uint8_t*)calloc(1,sizeof(uint8_t) * plainLen + 16);
	uint32_t decLen = 0;
	
	uint8_t* dec1 = NULL;
	dec1 = (uint8_t*)malloc(sizeof(uint8_t) * plainLen + 16);
	uint32_t decLen1 = 0;

	uint8_t* plainHex = NULL;
	plainHex = (uint8_t*)malloc((sizeof(uint8_t) * plainLen + 16) * 2 + 1);
	uint32_t plainHexLen = 0;
	
	uint8_t* decHex = NULL;
	decHex = (uint8_t*)malloc((sizeof(uint8_t) * plainLen + 16) * 2 + 1);
	uint32_t decHexLen = 0;

	uint8_t iv[BLOCKSIZE] = { 0x00, };
	uint32_t ivLen = BLOCKSIZE;
	
	int res = 0;
	int i = 0;
	
	res = edge_crypto_init(NULL);
	if(res != 0){
		printf("edge_crypto_init_Err Code : %d\n", res);
		return res;
	}
	
	edge_random_byte(key, keyLen);
	edge_random_byte(iv, ivLen);		
	
	memset(&param, 0, sizeof(test_param));
	memcpy(param.m_modeparam.m_iv, iv, ivLen);
	param.m_modeparam.m_ivlength = ivLen;

	printf("\n=============================== Main Start ===============================\n\n");

	res = dataToHex(plain, plainLen, plainHex, &plainHexLen); 
	if(res != CONVERT_OK){
		printf("dataToHex Err Code : %d\n", res);
		return res;
	}
	
	printf("Plain Data : %s\n",plain);	
	printf("Plain Data Len : %d\n",plainLen);
	
	printf("Hex Plain Data at main : %s\n", plainHex);
	printf("Hex Plain Data Len at main : %d\n", plainHexLen);
	
	printf("\n========================= CBC Enc made Start =======================\n\n");
	
	res = cbcEnc(cipherId, &param, plain, plainLen, out, &outLen, key, keyLen);		
	if(res != CONVERT_OK){
		printf("cbcEnc Err Code : %d\n", res);
		return res;
	}

	res = dataToHex(out, outLen, outHex, &outHexLen); 
	if(res != CONVERT_OK){
		printf("dataToHex Err Code : %d\n", res);
		return res;
	}

	printf("Enc Data Len at main : %d\n", outLen);
	printf("Hex Enc Data at main : %s\n", outHex);
	printf("Hex Enc Data Len at main : %d\n", outHexLen);
	
	printf("\n=========================== CBC Dec(Library)  Start =======================\n\n");
	
	memset(&param1, 0, sizeof(EDGE_CIPHER_PARAMETERS));
	memcpy(param1.m_modeparam.m_iv, iv, ivLen);
	param1.m_mode = EDGE_CIPHER_MODE_CBC;
	param1.m_padding = EDGE_CIPHER_PADDING_PKCS5;
	param1.m_modeparam.m_ivlength = ivLen; 
	
	///////////////////////////////////////////////////////
	
	res = edge_dec(cipherId, key, keyLen, &param1, out, outLen, dec, &decLen);
	if(res != 0){
		printf("cbcEnc Err Code : %d\n", res);
		return res;
	} 

	res = dataToHex(dec, decLen, decHex, &decHexLen); 
	if(res != CONVERT_OK){
		printf("dataToHex Err Code : %d\n", res);
		return res;
	}

	printf("Dec Data at main : %s\n", dec);
	printf("Dec Data Len at main : %d\n", decLen);
	printf("Hex Dec Data at main : %s\n", decHex);
	printf("Hex Dec Data Len at main : %d\n", decHexLen);

	strCompare(plainHex, decHex, plainHexLen, decHexLen);
	
	printf("\n========================= CBC Enc (Libray)  Start =======================\n\n");

	memset(&param1, 0, sizeof(EDGE_CIPHER_PARAMETERS)); 
	memcpy(param1.m_modeparam.m_iv, iv, ivLen);
	param1.m_mode = EDGE_CIPHER_MODE_CBC; 
	param1.m_padding = EDGE_CIPHER_PADDING_PKCS5; 
	param1.m_modeparam.m_ivlength = ivLen; 
	
	res = edge_enc(cipherId, key, keyLen, &param1, plain, plainLen, out1, &outLen1); 
	if(res != 0){
		printf("cbcEnc Err Code : %d\n", res);
		return res;
	} 

	//memset(outHex, 0, outHexLen);
	res = dataToHex(out1, outLen1, outHex, &outHexLen); 
	if(res != CONVERT_OK){
		printf("dataToHex Err Code : %d\n", res);
		return res;
	}

	printf("Plain Data : %s\n",plain);	
	printf("Plain Data Len : %d\n",plainLen);
	
	printf("Enc Data Len at main : %d\n", outLen1);
	printf("Hex Enc Data at main : %s\n", outHex);
	printf("Hex Enc Data Len at main : %d\n", outHexLen);
	
	printf("\n========================= CBC Dec made Start =======================\n\n");

	memset(&param, 0, sizeof(test_param));
	memcpy(param.m_modeparam.m_iv, iv, ivLen);
	param.m_modeparam.m_ivlength = ivLen; 
			
	res = cbcDec(cipherId, &param, out1, outLen1, dec1, &decLen1, key, keyLen); 
	if(res != CONVERT_OK){
		printf("cbcEnc Err Code : %d\n", res);
		return res;
	} 
	
	res = dataToHex(dec1, decLen1, decHex, &decHexLen); 
	if(res != CONVERT_OK){
		printf("dataToHex Err Code : %d\n", res);
		return res;
	}

	printf("Dec Data at main : %s\n", dec1);
	
	printf("Dec Data Len at main : %d\n", decLen1);
	printf("Hex Dec Data  at main : %s\n", decHex);
	printf("Hex Dec Data Len at main : %d\n", decHexLen);

	strCompare(plainHex, decHex, plainHexLen, decHexLen);
	
	}
	
	/*
	else if(strcmp(argv[1], "CFB") == 0) {
	
		printf("\n========================= CFB Enc made Start =======================\n\n");
		
		res = cfbEnc(cipherId, &param, plain, plainLen, out, &outLen, key, keyLen);
		if(res != CONVERT_OK){
			printf("cbcEnc Err Code : %d\n", res);
			return res;
		}
			
		res = dataToHex(out, outLen, outHex, &outHexLen); 
		if(res != CONVERT_OK){
			printf("dataToHex Err Code : %d\n", res);
			return res;
		}

		printf("Enc Data Len at main : %d\n", outLen);
		printf("Hex Enc Data at main : %s\n", outHex);
		printf("Hex Enc Data Len at main : %d\n", outHexLen);
		
		
		printf("\n=========================== CFB Dec (Library) Start =======================\n\n");
		
		memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));

		memcpy(param1.m_modeparam.m_iv, iv, ivLen);
		param1.m_mode = EDGE_CIPHER_MODE_CFB;
		param1.m_padding = EDGE_CIPHER_PADDING_PKCS5;
		param1.m_modeparam.m_ivlength = ivLen; 

		res = edge_dec(cipherId, key, keyLen, &param1, out, outLen, dec, &decLen);
		if(res != 0){
			printf("cbcEnc Err Code : %d\n", res);
			return res;
		} 

		res = dataToHex(dec, decLen, decHex, &decHexLen); 
		if(res != CONVERT_OK){
			printf("dataToHex Err Code : %d\n", res);
			return res;
		}

		printf("Dec Data at main : %s\n", dec);
		printf("Dec Data Len at main : %d\n", decLen);
		printf("Hex Dec Data at main : %s\n", decHex);
		printf("Hex Dec Data Len at main : %d\n", decHexLen);
	
		strCompare(plainHex, decHex, plainHexLen, decHexLen);
	
		printf("\n========================= CFB Enc (Library) Start =======================\n\n");

		memset(&param1, 0, sizeof(EDGE_CIPHER_PARAMETERS)); 
		memcpy(param1.m_modeparam.m_iv, iv, ivLen);
		param1.m_mode = EDGE_CIPHER_MODE_CFB; 
		param1.m_padding = EDGE_CIPHER_PADDING_PKCS5; 
		param1.m_modeparam.m_ivlength = ivLen; 
		
		res = edge_enc(cipherId, key, keyLen, &param1, plain, plainLen, out1, &outLen1); 
		if(res != 0){
			printf("cbcEnc Err Code : %d\n", res);
			return res;
		} 

		memset(outHex, 0, outHexLen);

		res = dataToHex(out1, outLen1, outHex, &outHexLen); 
		if(res != CONVERT_OK){
			printf("dataToHex Err Code : %d\n", res);
			return res;
		}

		printf("Plain Data : %s\n",plain);	
		printf("Plain Data Len : %d\n",plainLen);
		
		printf("Enc Data Len at main : %d\n", outLen1);
		printf("Hex Enc Data at main : %s\n", outHex);
		printf("Hex Enc Data Len at main : %d\n", outHexLen);
		
		printf("\n========================= CFB Dec made Start =======================\n\n");

		memset(&param, 0, sizeof(test_param));
		memcpy(param.m_modeparam.m_iv, iv, ivLen);
		param.m_mode = EDGE_CIPHER_MODE_CFB; 
		param.m_padding = EDGE_CIPHER_PADDING_PKCS5; 
		param.m_modeparam.m_ivlength = ivLen; 
			
		res = cfbDec(cipherId, &param, out1, outLen1, dec1, &decLen1, key, keyLen); 
		if(res != CONVERT_OK){
			printf("cbcEnc Err Code : %d\n", res);
			return res;
		} 
		
		res = dataToHex(dec1, decLen1, decHex, &decHexLen); 
		if(res != CONVERT_OK){
			printf("dataToHex Err Code : %d\n", res);
			return res;
		}

		printf("Dec Data at main : %s\n", dec1);
		printf("Dec Data Len at main : %d\n", decLen1);
		printf("Hex Dec Data  at main : %s\n", decHex);
		printf("Hex Dec Data Len at main : %d\n", decHexLen);

		strCompare(plainHex, decHex, plainHexLen, decHexLen);
	}
	
	else if(strcmp(argv[1], "OFB") == 0){ 

	
		printf("\n========================= OFB Enc made Start =======================\n\n");
		
		res = ofbEnc(cipherId, &param, plain, plainLen, out, &outLen, key, keyLen);
		if(res != CONVERT_OK){
			printf("cbcEnc Err Code : %d\n", res);
			return res;
		}
			
		res = dataToHex(out, outLen, outHex, &outHexLen); 
		if(res != CONVERT_OK){
			printf("dataToHex Err Code : %d\n", res);
			return res;
		}

		printf("Enc Data Len at main : %d\n", outLen);
		printf("Hex Enc Data at main : %s\n", outHex);
		printf("Hex Enc Data Len at main : %d\n", outHexLen);
		
		printf("\n=========================== OFB Dec(Library) Start =======================\n\n");
		
		memset(&param1, 0, sizeof(EDGE_CIPHER_PARAMETERS));

		memcpy(param1.m_modeparam.m_iv, iv, ivLen);
		param1.m_mode = EDGE_CIPHER_MODE_OFB;
		param1.m_padding = EDGE_CIPHER_PADDING_PKCS5;
		param1.m_modeparam.m_ivlength = ivLen; 

		res = edge_dec(cipherId, key, keyLen, &param1, out, outLen, dec, &decLen);
		if(res != 0){
			printf("cbcEnc Err Code : %d\n", res);
			return res;
		} 

		res = dataToHex(dec, decLen, decHex, &decHexLen); 
		if(res != CONVERT_OK){
			printf("dataToHex Err Code : %d\n", res);
			return res;
		}

		printf("Dec Data at main : %s\n", dec);
		printf("Dec Data Len at main : %d\n", decLen);
		printf("Hex Dec Data at main : %s\n", decHex);
		printf("Hex Dec Data Len at main : %d\n", decHexLen);

		strCompare(plainHex, decHex, plainHexLen, decHexLen);
		
		printf("\n========================= OFB Enc(Library) Start =======================\n\n");

		memset(&param1, 0, sizeof(EDGE_CIPHER_PARAMETERS)); 

		memcpy(param1.m_modeparam.m_iv, iv, ivLen);
		param1.m_mode = EDGE_CIPHER_MODE_OFB; 
		param1.m_padding = EDGE_CIPHER_PADDING_PKCS5; 
		param1.m_modeparam.m_ivlength = ivLen; 
		
		res = edge_enc(cipherId, key, keyLen, &param1, plain, plainLen, out1, &outLen1); 
		if(res != 0){
			printf("cbcEnc Err Code : %d\n", res);
			return res;
		} 

		memset(outHex, 0, outHexLen);

		res = dataToHex(out1, outLen1, outHex, &outHexLen); 
		if(res != CONVERT_OK){
			printf("dataToHex Err Code : %d\n", res);
			return res;
		}

		printf("Plain Data : %s\n",plain);	
		printf("Plain Data Len : %d\n",plainLen);
		printf("Enc Data Len at main : %d\n", outLen1);
		printf("Hex Enc Data at main : %s\n", outHex);
		printf("Hex Enc Data Len at main : %d\n", outHexLen);
		
		printf("\n========================= OFB Dec made Start =======================\n\n");
		
		res = ofbDec(cipherId, &param, out1, outLen1, dec1, &decLen1, key, keyLen); 
		if(res != CONVERT_OK){
			printf("cbcEnc Err Code : %d\n", res);
			return res;
		} 
		
		res = dataToHex(dec1, decLen1, decHex, &decHexLen); 
		if(res != CONVERT_OK){
			printf("dataToHex Err Code : %d\n", res);
			return res;
		}

		printf("Dec Data at main : %s\n", dec1);
		printf("Dec Data Len at main : %d\n", decLen1);
		printf("Hex Dec Data  at main : %s\n", decHex);
		printf("Hex Dec Data Len at main : %d\n", decHexLen);

		strCompare(plainHex, decHex, plainHexLen, decHexLen);
	}
	
	else{	
		printf("\n*****************************************************************************************************\n");
		printf("\nPut Command\nWhen you operate this program you have to put command CBC or CFB or OFB next to name of operated file\n\n");
	
	
		return ERR;
	}
	*/
	
	free(plainHex);
	free(decHex);
	free(out);
	free(dec);
	free(out1);
	free(dec1);
	free(outHex);

	edge_crypto_final();
		
	printf("\n========================= end main =================================\n\n");

	return CONVERT_OK;
}

