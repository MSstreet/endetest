#include <stdio.h>
#include "ende.h"
#include "hexende.h"

int main(int argc, char* argv[]){
	
	EDGE_CIPHER_PARAMETERS param1; 
	
	setting_var set;
	uint32_t cipherId = EDGE_CIPHER_ID_SEED128; 
	
	uint8_t key[BLOCKSIZE] = { 0x00, };
	uint32_t keyLen = BLOCKSIZE;

	uint8_t* plain = "start11111111dsjlfkskjfstart1234567890123456endendend";
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
	
	char *opt = NULL;	
	opt = argv[1];

	if(argc < 2 || argc >= 3){
		


		printf("\n*****************************************************************************************************\n");
		printf("\nPut Command\nWhen you operate this program you have to put command CBC or CFB or OFB next to name of operated file\n");	
	
	}

	else if(strcmp(argv[1], "CBC") == 0 || strcmp(argv[1], "CFB") == 0 || strcmp(argv[1], "OFB") == 0 ) {

		res = edge_crypto_init(NULL);
		if(res != 0){
			printf("edge_crypto_init_Err Code : %d\n", res);
			return res;
		}
		
		edge_random_byte(key, keyLen);
		edge_random_byte(iv, ivLen);		






		printf("\n=============================== Main Start ===============================\n\n");

		res = dataToHex(plain, plainLen, plainHex, &plainHexLen); 
		if(res != CONVERT_OK){
			printf("dataToHex Err Code : %d\n", res);
			return res;
		}
		
		printf("Plain Data : %s\n",plain);	
		printResult(plainLen, plainHex, plainHexLen);







		printf("\n========================= Enc made Start =======================\n\n");
	
		memset(&set, 0, sizeof(setting_var));
		settingVarFunc(&set,cipherId, plainLen);
		//set.cipheId = EDGE_CIPHER_ID_SEED128;

		if(strcmp(opt, "CBC") == 0){
			set.m_mode = CBC;
		}else if(strcmp(opt, "CFB") == 0){
			set.m_mode = CFB;
		}else if(strcmp(opt, "OFB") == 0){
			set.m_mode = OFB;
		}else{
			printf("It is wrong mode\n");
			return ERR;
		}
		
		memcpy(set.iv, iv, ivLen);
		memcpy(set.key, key, keyLen);
		
		res = ms_enc(&set, plain, plainLen, out, &outLen);
		if(res != CONVERT_OK){
			printf("ms_enc Err Code : %d\n", res);
			return res;
		}
		
		res = dataToHex(out, outLen, outHex, &outHexLen);
		if(res != CONVERT_OK){
			printf("dataToHex Err Code : %d\n", res);
			return res;
		}

		printResult(outLen, outHex, outHexLen);


		
		
		
		
		
		
		printf("\n========================= Dec(Library) Start =======================\n\n");

		memset(&param1, 0, sizeof(EDGE_CIPHER_PARAMETERS));
		memcpy(param1.m_modeparam.m_iv, iv, ivLen);
		param1.m_padding = EDGE_CIPHER_PADDING_PKCS5;
		param1.m_modeparam.m_ivlength = ivLen; 
		
		switch(set.m_mode){
			
			case CBC :
				param1.m_mode = EDGE_CIPHER_MODE_CBC;
				break;
			
			case CFB :
				param1.m_mode = EDGE_CIPHER_MODE_CFB;
				break;
			
			case OFB :
				param1.m_mode = EDGE_CIPHER_MODE_OFB;
				break;

			default : 
				printf("It is wrrong number of mode\n");
				return ERR;
		
		}

		res = edge_dec(set.cipherId, key, keyLen, &param1, out, outLen,dec, &decLen);
		if(res != 0){
			printf("edge_dec Err Code : %d\n", res);
			return res;
		}

		res = dataToHex(dec, decLen, decHex, &decHexLen);
		if(res != CONVERT_OK){
			printf("dataToHex Err Code : %d\n", res);
			return res;
		}

		printResult(decLen, decHex, decHexLen);
		strCompare(plainHex, decHex, plainHexLen, decHexLen);


		
		
		
		
		
		
		
		printf("\n========================= Enc(Library) Start =======================\n\n");
		
		res = edge_enc(set.cipherId, key, keyLen, &param1, plain, plainLen, out1, &outLen1);
		if(res != 0){
			printf("edge_enc Err Code : %d\n", res);
			return res;
		}
		
		res = dataToHex(out1, outLen1, outHex, &outHexLen);
		if(res != CONVERT_OK){
			printf("dataToHex Err Code : %d\n", res);
			return res;
		}

		printResult(outLen1, outHex, outHexLen);

		
		
		
		
		
		
		
		
		
		
		
		printf("\n========================= Dec made Start =======================\n\n");
		
		res = ms_dec(&set, out1, outLen1, dec1, &decLen1);	
		if(res != CONVERT_OK){
			printf("ms_dec Err Code : %d\"", res);
			
		}

		res = dataToHex(dec, decLen, decHex, &decHexLen);
		if(res != CONVERT_OK){
			printf("dataToHex Err Code : %d\n", res);
			return res;
		}

		printResult(decLen, decHex, decHexLen);
		strCompare(plainHex, decHex, plainHexLen, decHexLen);
	}
	
	
	
	
	
	
	
	else{
		printf("\n*****************************************************************************************************\n");
		printf("\nPut Command\nWhen you operate this program you have to put command CBC or CFB or OFB next to name of operated file\n\n");

		return ERR;
	}

	
	
	
	free(plainHex);
	free(decHex);
	free(out);
	free(dec);
	free(out1);
	free(dec1);
	free(outHex);

	edge_crypto_final();

	printf("\n========================= End main =======================\n\n");

	return CONVERT_OK;
}	
