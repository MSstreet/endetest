#include <stdio.h>
#include "ende.h"
#include "edge_crypto.h"

void printResult(uint32_t dataLen, uint8_t* hexData, uint32_t hexLen){

	printf("Result Data Len : %d\n", dataLen);
	printf("Result Data Hex : %s\n", hexData);
	printf("Result Data Hex Len : %d\n", hexLen);

}

void strCompare(uint8_t* plain, uint8_t* decString, uint32_t plainLen, uint32_t DecLen){
	
	//int plainLen = strlen(plain);
	//int decStringLen = strlen(decString);

	if((strcmp(plain, decString) != 0) || (plainLen != DecLen)){
		printf("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
		printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
		printf("Plain and DecData is not same!!!!!!!!!!!!\n");
	
	}else{
		printf("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
		printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
		printf("Plina and DecData is same!!!!!!!!!!!!\n");	
	}
	
}

int settingVarFunc(setting_var* set, test_param* param, uint32_t inDataLen){

	int blockNum_tmp = 0;

	memset(set -> plain_tmp, 0x00, BLOCKSIZE);
	memset(set -> iv, 0x00, BLOCKSIZE);
	memset(set -> tmpEnc, 0x00, BLOCKSIZE);
	memset(set -> cryped_tmp, 0x00, BLOCKSIZE);
	memset(set -> tmpDec, 0x00, BLOCKSIZE);

	memcpy(set -> iv, param->m_modeparam.m_iv, param -> m_modeparam.m_ivlength);

	set -> plainLen = BLOCKSIZE;
	set -> crypedLen = BLOCKSIZE;
	set -> ivLen = param -> m_modeparam.m_ivlength;
	set -> tmpEncLen = BLOCKSIZE;
	set -> tmpDecLen = BLOCKSIZE;
	set -> paddingNum = BLOCKSIZE - (inDataLen % BLOCKSIZE); 

	set -> blockNum = inDataLen / BLOCKSIZE + 1;
	blockNum_tmp = set -> blockNum;

	set -> totalEncLen = blockNum_tmp * BLOCKSIZE;

	return CONVERT_OK;
}

int cbcEnc(uint32_t cipherId, test_param* param, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen){

	if(inData == NULL) return ERR;
       	if(key == NULL) return ERR;
	
	setting_var set;
	
	int i = 0, j = 1;
	int index = 0;
	
	int tmp = 0;
	int res = 0;

	memset(&set, 0x00, sizeof(setting_var)); 
	settingVarFunc(&set, param, inDataLen);

//	printf("\n========================= CBC Enc made Start =======================\n\n");

	while(i < set.totalEncLen){	
		
		index = 0;








		for(; index < BLOCKSIZE; index++){
								
			if(j == set.blockNum){//last

				if(index >= BLOCKSIZE - set.paddingNum){
					
					set.plain_tmp[index] = set.paddingNum;			
				}else{
					
					set.plain_tmp[index] = *(inData + i + index);
				}
			}else{
				set.plain_tmp[index] = *(inData + i + index);	
			}
		}
		
	






		
		if(i == 0){
			for(index = 0; index < BLOCKSIZE; index++){
				
				set.plain_tmp[index] = set.plain_tmp[index] ^ set.iv[index];				
			}
						
			
			
			
			res = oneBlockEcbEnc(cipherId, &set, key, keyLen); 
			if(res != CONVERT_OK){
				printf("oneBlockCbcEnc Err Code : %d\n", res);
				return res;
			}				
		}
		
		
		else{
			
			for(index = 0; index < 16; index++){
				
				set.plain_tmp[index] = set.plain_tmp[index] ^ set.tmpEnc[index];
			
			}

			memset(set.tmpEnc, 0x00, set.tmpEncLen);
	
			res = oneBlockEcbEnc(cipherId, &set, key, keyLen);
			if(res != CONVERT_OK){
				printf("oneBlockCbcEnc Err Code : %d\n", res);
				return res;
			}
		}
		
		
		
		for(index = 0; index < set.tmpEncLen; index++){
			
			*(outData + i + index) = set.tmpEnc[index];
			
		}
		
		
		
		
		i+= BLOCKSIZE;
		j++;
	
		
		
		
		memset(set.plain_tmp, 0x00, set.plainLen);
		*outDataLen += set.tmpEncLen; 

	}	
	memset(set.tmpEnc, 0x00, set.tmpEncLen);
	
	*(outData + *outDataLen + 1) = '\0';
		
	 return CONVERT_OK;
}




int cbcDec(uint32_t cipherId, test_param* param, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen){

	if(inData == NULL) return ERR;
	if(key == NULL) return ERR;
	
	setting_var set;
	
	int i = 0, j = 1;
	int index = 0;
	
	int res = 0;
	
	int padding = 0;	
	uint32_t paddingOper = 0;

	memset(&set, 0x00, sizeof(setting_var)); 
	settingVarFunc(&set, param, inDataLen);
	
	uint8_t xorOper[16] = { 0x00, };
	uint32_t xorOperLen = 16;

	while(i < inDataLen){
		
		index = 0;
		



		for(; index < 16; index++){
			set.cryped_tmp[index] = *(inData + i + index);	
		}
		
		
		
		
		
		if(i == 0){ //first block
			
			res = oneBlockEcbDec(cipherId, &set, key, keyLen);
		       if(res != CONVERT_OK){
				return res;  
		 
		       } 
		
		       for(index = 0; index < BLOCKSIZE; index++){
				set.tmpDec[index] = set.tmpDec[index] ^ set.iv[index];
			}		
		
		
		
		
		}else{ //after first block
			
			memset(set.tmpDec, 0x00, set.tmpDecLen);		

			res = oneBlockEcbDec(cipherId, &set, key, keyLen);
			if(res != CONVERT_OK){
				return res;	
			}
			
			for(index = 0; index < BLOCKSIZE; index++){
				set.tmpDec[index] = set.tmpDec[index] ^ xorOper[index];
			}
		}
		



		memset(xorOper, 0x00, xorOperLen);
		
		for(index = 0; index < 16; index++){

			*(outData + i + index) = set.tmpDec[index];
			
			xorOper[index] = set.cryped_tmp[index];
		}

		*(outData + i + index) = '\0';

		memset(set.cryped_tmp, 0x00, set.crypedLen);  
		*outDataLen += set.tmpDecLen;
	
		i += 16;
	}
	
	
	
	
	paddingOper = *outDataLen - 1;
	padding = *(outData + paddingOper);
	
	if(padding < 1 || padding > 16)
		return ERR;
	
	*outDataLen -= padding;
	while(padding-- != 0) {
		*(outData + paddingOper--) = '\0';
	}

	return CONVERT_OK;
}

int cfbEnc(uint32_t cipherId,  test_param* param, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen){
	
	if(inData == NULL) return ERR;
	if(key == NULL) return ERR;

	setting_var set;

	int i = 0, j = 1;
	int index = 0;

	int tmp = 0;
	int res = 0;

	uint8_t tmpXor[BLOCKSIZE] = { 0x00, };
	uint32_t tmpXorLen = BLOCKSIZE;

	uint8_t plainTmp[BLOCKSIZE] = { 0x00, };
	
	memset(&set, 0x00, sizeof(setting_var));
	settingVarFunc(&set, param, inDataLen);	
	
	while(i < set.totalEncLen){	
		
 		index = 0;

		for(; index < BLOCKSIZE; index++){					
			if(j == set.blockNum){//last
				
				if(index >= BLOCKSIZE - set.paddingNum){
					set.plain_tmp[index] = set.paddingNum;	
														
				}else{
					set.plain_tmp[index] = *(inData + i + index);									
				}
			
			}else{
				set.plain_tmp[index] = *(inData + i + index);
			}
		
		}
			
		if(i == 0){
			
			for(index = 0; index < BLOCKSIZE; index++){
				
				plainTmp[index] = set.plain_tmp[index];
				set.plain_tmp[index] = set.iv[index];
			}
				
			set.plainLen = set.ivLen;

			res = oneBlockEcbEnc(cipherId, &set, key, keyLen);
			if(res != CONVERT_OK){
				printf("oneBlockCbcEnc Err Code : %d\n", res);
				return res;
			}	
			
			memset(set.plain_tmp, 0x00, set.plainLen);

			for(index = 0; index < BLOCKSIZE; index++){
				set.plain_tmp[index] = plainTmp[index] ^ set.tmpEnc[index];
				tmpXor[index] = set.plain_tmp[index];
			}
		}

		else{
					
			for(index = 0; index < BLOCKSIZE; index++){
				plainTmp[index] = set.plain_tmp[index];
				
				set.plain_tmp[index] = tmpXor[index];
			}
				
			set.plainLen = tmpXorLen;

			res = oneBlockEcbEnc(cipherId, &set, key, keyLen);
			if(res != CONVERT_OK){
				printf("oneBlockCbcEnc Err Code : %d\n", res);
				return res;
			}
			
			memset(tmpXor, 0x00, tmpXorLen);
			
			for(index = 0; index < BLOCKSIZE; index++){
				tmpXor[index] = plainTmp[index] ^ set.tmpEnc[index];
			}
		}
		

		for(index = 0; index < set.tmpEncLen; index++){	
			*(outData + i + index) = tmpXor[index];
		}

		i+= BLOCKSIZE;
		j++;
	
		memset(set.plain_tmp, 0, set.plainLen);
		*outDataLen += set.tmpEncLen; 

	}
	
	memset(set.tmpEnc, 0x00, set.tmpEncLen);
	
	*(outData + *outDataLen + 1) = '\0';
	
	 return CONVERT_OK;
}

int cfbDec(uint32_t cipherId, test_param* param, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen){
	
	if(inData == NULL) return ERR;
	if(key == NULL) return ERR;
	
	setting_var set;
	
	memset(&set, 0x00, sizeof(setting_var)); 
	settingVarFunc(&set, param, inDataLen);
	
	uint8_t xorOper[16] = { 0x00, };
	uint32_t xorOperLen = 16;
	
	int i = 0, j = 1;
	int index = 0;
	
	int res = 0;
	
	int padding = 0;
	uint32_t paddingOper = 0;
	
	//uint8_t crypedTmp[16] = { 0x00, };
	//uint32_t crypedLen = 16;
	
	while(i < inDataLen){
		
		index = 0;
		
		for(; index < 16; index++){
			set.cryped_tmp[index] = *(inData + i + index);
		}
		
		if( i == 0){ //first block
	
			for(index = 0; index < BLOCKSIZE; index++){
				set.plain_tmp[index] = set.iv[index];
			}

			set.plainLen = set.ivLen;

			res = oneBlockEcbEnc(cipherId, &set, key, keyLen);
		       if(res != CONVERT_OK){
				return res;  
		       } 	       
			for(index = 0; index < BLOCKSIZE; index++){
				
				set.tmpDec[index] = set.tmpEnc[index] ^ set.cryped_tmp[index];
			}
		}else{ //after first block
			
			memset(set.tmpEnc, 0x00, set.tmpEncLen);		

			res = oneBlockEcbEnc(cipherId, &set, key, keyLen);
			if(res != CONVERT_OK){
				return res;	
			}
			
			for(index = 0; index < BLOCKSIZE; index++){
				set.tmpDec[index] = set.cryped_tmp[index] ^ set.tmpEnc[index];
			}
		
		}
		
		memset(set.plain_tmp, 0x00, set.plainLen);
		
		for(index = 0; index < BLOCKSIZE; index++){

			*(outData + i + index) = set.tmpDec[index];
			
			set.plain_tmp[index] = set.cryped_tmp[index];
		}
		
		set.plainLen = set.crypedLen;

		*(outData + i + index) = '\0';

		memset(set.cryped_tmp, 0x00, set.crypedLen);  
		*outDataLen += set.tmpEncLen;
	
		i += 16;
	}
	
	paddingOper = *outDataLen - 1;
	padding = *(outData + paddingOper);
	
	if(padding < 1 || padding > 16)
		return ERR;

	*outDataLen -= padding;
		
	while(padding-- != 0) {
		
		*(outData + paddingOper--) = '\0';
			
	}
	return CONVERT_OK;

}

int ofbEnc(uint32_t cipherId,  test_param* param, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen){
	
	if(inData == NULL) return ERR;
	if(key == NULL) return ERR;
	
	setting_var set;	

	uint8_t plainTmp[BLOCKSIZE] = { 0x00, };
	uint32_t plainTmpLen = BLOCKSIZE;

	uint8_t tmpXor[BLOCKSIZE] = { 0x00, };
	uint32_t tmpXorLen = BLOCKSIZE;

	int i = 0, j = 1;
	int index = 0;

	int tmp = 0;
	int res = 0;
		
	memset(&set, 0x00, sizeof(setting_var));
	settingVarFunc(&set, param, inDataLen);	

	while(i < set.totalEncLen){	
		
 		index = 0;

		for(; index < BLOCKSIZE; index++){					
			if(j == set.blockNum){//last
				
				if(index >= BLOCKSIZE - set.paddingNum){
					set.plain_tmp[index] = set.paddingNum;	
														
				}else{
					set.plain_tmp[index] = *(inData + i + index);									
				}
			}else{
				set.plain_tmp[index] = *(inData + i + index);
			}
		
		}		
		if(i == 0){
				
			for(index = 0; index < BLOCKSIZE; index++){
				
				plainTmp[index] = set.plain_tmp[index];
				set.plain_tmp[index] = set.iv[index];
			}	
			
			set.plainLen = set.ivLen;

			res = oneBlockEcbEnc(cipherId,&set, key, keyLen);
			if(res != CONVERT_OK){
				printf("oneBlockCbcEnc Err Code : %d\n", res);
				return res;
			}	
			
			memset(set.plain_tmp, 0x00, set.plainLen);

			for(index = 0; index < BLOCKSIZE; index++){

				set.plain_tmp[index] = plainTmp[index] ^ set.tmpEnc[index];
				tmpXor[index] = set.plain_tmp[index];
			}
		
			for(index = 0; index < set.tmpEncLen; index++){
			
				*(outData + i + index) = tmpXor[index];
			}

		}
		else{
						
			for(index = 0; index < BLOCKSIZE; index++){
				plainTmp[index] = set.plain_tmp[index];
				set.plain_tmp[index] = set.tmpEnc[index];		
			}
			
			set.plainLen =  set.tmpEncLen;
			memset(set.tmpEnc , 0x00, set.tmpEncLen);
	
			res = oneBlockEcbEnc(cipherId,&set, key, keyLen);
			if(res != CONVERT_OK){
				printf("oneBlockCbcEnc Err Code : %d\n", res);
				return res;
			}

			for(index = 0; index < BLOCKSIZE; index++){
								
				tmpXor[index] = plainTmp[index] ^ set.tmpEnc[index];
			}
			
			for(index = 0; index < set.tmpEncLen; index++){
			
				*(outData + i + index) = tmpXor[index];
			}
		}
		i+= BLOCKSIZE;
		j++;
	
		memset(set.plain_tmp, 0, set.plainLen);
		*outDataLen += set.tmpEncLen; 

	}
	
	*(outData + *outDataLen + 1) = '\0';
	
	 return CONVERT_OK;
}

int ofbDec(uint32_t cipherId, test_param* param, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen){

	if(inData == NULL) return ERR;
	if(key == NULL) return ERR;		
	
	setting_var set;
	
	memset(&set, 0x00, sizeof(setting_var));
	settingVarFunc(&set, param, inDataLen);	
	
	uint8_t crypedTmp[BLOCKSIZE] = { 0x00, };
	uint32_t crypedTmpLen = BLOCKSIZE;

	int padding = 0;
	
	int i = 0, j = 1;
	int index = 0;
	
	int res = 0;
	uint32_t paddingOper = 0;

	while(i < inDataLen){
		
		index = 0;
		
		for(; index < BLOCKSIZE; index++){
			
			set.cryped_tmp[index] = *(inData + i + index);
			
		}

		if( i == 0){ //first block

			for(index = 0; index < BLOCKSIZE; index++){
				set.plain_tmp[index] = set.iv[index];
			}	

			set.plainLen = set.ivLen;

			res = oneBlockEcbEnc(cipherId, &set, key, keyLen);
		       if(res != CONVERT_OK){
				return res;  
		       }   
			for(index = 0; index < BLOCKSIZE; index++){
				
				set.tmpDec[index] = set.tmpEnc[index] ^ set.cryped_tmp[index];
				
			}
		       	
			for(index = 0; index < set.tmpEncLen; index++){

				*(outData + i + index) = set.tmpDec[index];
			
			}

			*outDataLen += set.tmpEncLen;	
		}
		
		else{ //after first block
						
			for(index = 0; index < BLOCKSIZE; index++){

				set.plain_tmp[index] = set.tmpEnc[index];	
			
			}

			memset(set.tmpEnc, 0x00, set.tmpEncLen);
		
			res = oneBlockEcbEnc(cipherId ,&set, key, keyLen);
			if(res != CONVERT_OK){
				return res;	
			}
			memset(set.tmpDec, 0x00, set.tmpDecLen);

			for(index = 0; index < BLOCKSIZE; index++){
				set.tmpDec[index] = set.cryped_tmp[index] ^ set.tmpEnc[index];
			}
			
			for(index = 0; index < set.tmpEncLen; index++){
			
				*(outData + i + index) = set.tmpDec[index];

			}
	
			*outDataLen += set.tmpEncLen;

		}

		*(outData + i + index) = '\0';

		memset(set.cryped_tmp, 0x00, set.crypedLen);  
			
		i += 16;
	}
		
	paddingOper = *outDataLen - 1;
	padding = *(outData + paddingOper);

	if(padding < 1 || padding > 16)
		return ERR;

	*outDataLen -= padding;
		
	while(padding-- != 0) {
		
		*(outData + paddingOper--) = '\0';
			
	}
	return CONVERT_OK;
}


int oneBlockEcbEnc(uint32_t cipherId, setting_var* set, uint8_t* key, uint32_t keyLen){

	if(set -> plain_tmp == NULL) return ERR;
	if(key == NULL) return ERR;
	
	int res = 0;	

	EDGE_CIPHER_PARAMETERS param;
	memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));

	param.m_mode = EDGE_CIPHER_MODE_CBC;
	param.m_padding = EDGE_CIPHER_PADDING_NONE;
	param.m_modeparam.m_ivlength = 16; 

	res = edge_enc(cipherId, key, keyLen, &param, set -> plain_tmp, set -> plainLen, set -> tmpEnc, &(set -> tmpEncLen));
	if(res != 0){
		printf("edge_enc Err Code : %d\n", res);
		return res;
	}

	return CONVERT_OK;
}

int oneBlockEcbDec(uint32_t cipherId, setting_var* set, uint8_t* key, uint32_t keyLen){

	if(set -> cryped_tmp == NULL) return ERR;
	if(key == NULL) return ERR;
	
	int res = 0;
	
	EDGE_CIPHER_PARAMETERS param;
	memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));

	param.m_mode = EDGE_CIPHER_MODE_CBC; 
	param.m_padding = EDGE_CIPHER_PADDING_NONE; 
	param.m_modeparam.m_ivlength = 16; 
	
	res = edge_dec(cipherId, key, keyLen, &param, set -> cryped_tmp, set -> crypedLen, set -> tmpDec, &(set -> tmpDecLen));
	if(res != 0){
		printf("edge_dec Err Code : %d\n", res);
		return res;
	}
	
	memset(param.m_modeparam.m_iv, 0x00, param.m_modeparam.m_ivlength);

	return CONVERT_OK;
}



int ms_enc(uint32_t cipherId,  test_param* param, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen){
	
	//EDGE_CIPHER_PARAMETERS param1;

	int res = 0;
	
	switch(param->m_mode){

		case CBC:
			
			res = cbcEnc(cipherId, param, inData, inDataLen, outData, outDataLen, key, keyLen);
			if(res != CONVERT_OK){
				printf("cbcEnc Err Code : %d\n", res);
				return res;
			}
			
			break;

		case CFB:
			res = cfbEnc(cipherId, param, inData, inDataLen, outData, outDataLen, key, keyLen);
			if(res != CONVERT_OK){
				printf("cbcEnc Err Code : %d\n", res);
				return res;
			}

			break;

		case OFB:
			res = ofbEnc(cipherId, param, inData, inDataLen, outData, outDataLen, key, keyLen);
			if(res != CONVERT_OK){
				printf("cbcEnc Err Code : %d\n", res);
				return res;
			}
			
			break;

		default :
			printf("It is wrong number of mode\n");
			return ERR; 
	
	}		

	return CONVERT_OK;

}

int ms_dec(uint32_t cipherId, test_param* param, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen){
	
	int res = 0;
	
	switch(param->m_mode){

		case CBC:	
			res = cbcDec(cipherId, param, inData, inDataLen, outData, outDataLen, key, keyLen);
			if(res != CONVERT_OK){
				printf("cbcEnc Err Code : %d\n", res);
				return res;
			}
			
			break;

		case CFB:
			res = cfbDec(cipherId, param, inData, inDataLen, outData, outDataLen, key, keyLen);
			if(res != CONVERT_OK){
				printf("cbcEnc Err Code : %d\n", res);
				return res;
			}
			
			break;

		case OFB:
			res = ofbDec(cipherId, param, inData, inDataLen, outData, outDataLen, key, keyLen);
			if(res != CONVERT_OK){
				printf("cbcEnc Err Code : %d\n", res);
				return res;
			}
			
			break;

		default :
			printf("It is wrong number of mode\n");
			return ERR; 
	
	}		

	return CONVERT_OK;



}


