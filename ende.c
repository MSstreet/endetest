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

int padding(setting_var* set, int blockCnt, int lastBlockCompare, uint8_t* inData){

	int index = 0;

	for(; index < BLOCKSIZE; index++){

		if(lastBlockCompare == set -> blockNum){
			
			if(index >= BLOCKSIZE - (set -> paddingNum)){
				set -> plain_tmp[index] = set -> paddingNum;
			}
			
			else{
				set-> plain_tmp[index] = *(inData + blockCnt + index);	
			}
		}
		else{
			set -> plain_tmp[index] = *(inData + blockCnt + index);
		}
	}
		
	return CONVERT_OK;
	
}

int paddingCut(uint32_t paddingOper,uint32_t *outDataLen, uint32_t padding, uint8_t* outData){
	
	paddingOper = *outDataLen - 1;
	padding = *(outData + paddingOper);

	if(padding < 1 || padding > 16)
		return ERR;

	*outDataLen -= padding;

	while(padding-- != 0){
		*(outData + paddingOper--) = '\0';
	}

	return CONVERT_OK;

}

int settingVarFunc(setting_var* set, uint32_t cipherId, uint32_t inDataLen){

	int blockNum_tmp = 0;

	memset(set -> plain_tmp, 0x00, BLOCKSIZE);
	memset(set -> cryped_tmp, 0x00, BLOCKSIZE);
	memset(set -> iv, 0x00, BLOCKSIZE);
	memset(set -> key, 0x00, BLOCKSIZE);

	set -> cipherId = cipherId;

	set -> plainLen = BLOCKSIZE;
	set -> crypedLen = BLOCKSIZE;
	set -> keyLen = BLOCKSIZE;
	set -> paddingNum = BLOCKSIZE - (inDataLen % BLOCKSIZE); 

	set -> blockNum = inDataLen / BLOCKSIZE + 1;
	blockNum_tmp = set -> blockNum;

	set -> totalEncLen = blockNum_tmp * BLOCKSIZE;

	return CONVERT_OK;
}

int cbcEnc(setting_var* set, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen){

	if(inData == NULL) return ERR;
       	if(set -> key == NULL) return ERR;
		
	int i = 0, j = 1;
	int index = 0;
	
	int tmp = 0;
	int res = 0;

	uint8_t tmpEnc[BLOCKSIZE] = { 0x00, };
	uint32_t tmpEncLen = BLOCKSIZE;

	while(i < set -> totalEncLen){	
		
		index = 0;

		res = padding(set,i, j, inData);
		if(res != CONVERT_OK){
			printf("pddingfunc Err Code : %d\n", res);
			return res;
		}
		
		if(i == 0){
			
			for(index = 0; index < BLOCKSIZE; index++){
				
				set -> plain_tmp[index] = set -> plain_tmp[index] ^ set -> iv[index];				
			}			
			
			res = oneBlockEcbEnc(set, tmpEnc, &tmpEncLen); 
			if(res != CONVERT_OK){
				printf("oneBlockCbcEnc Err Code : %d\n", res);
				return res;
			}				
		
		}else{
			
			for(index = 0; index < 16; index++){
				
				set -> plain_tmp[index] = set -> plain_tmp[index] ^ tmpEnc[index];
			
			}
			memset(tmpEnc, 0x00, tmpEncLen);
	
			res = oneBlockEcbEnc(set, tmpEnc, &tmpEncLen);
			if(res != CONVERT_OK){
				printf("oneBlockCbcEnc Err Code : %d\n", res);
				return res;
			}
		}
		
		for(index = 0; index < tmpEncLen; index++){
			
			*(outData + i + index) = tmpEnc[index];
			
		}
		
		i+= BLOCKSIZE;
		j++;
	
		memset(set -> plain_tmp, 0x00, set -> plainLen);
		*outDataLen += tmpEncLen; 
	}	
	
	memset(tmpEnc, 0x00, tmpEncLen);
	
	*(outData + *outDataLen + 1) = '\0';
		
	 return CONVERT_OK;
}


int cbcDec(setting_var* set, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen){

	if(inData == NULL) return ERR;
	if(set -> key == NULL) return ERR;
	
	int i = 0, j = 1;
	int index = 0;
	
	int res = 0;
	
	int padding = 0;	
	uint32_t paddingOper = 0;
	
	uint8_t xorOper[16] = { 0x00, };
	uint32_t xorOperLen = 16;

	uint8_t tmpDec[BLOCKSIZE] = { 0x00, };
	uint32_t tmpDecLen = BLOCKSIZE;

	while(i < inDataLen){
		
		index = 0;
		
		for(; index < 16; index++){
			set -> cryped_tmp[index] = *(inData + i + index);	
		}
		


		if(i == 0){ //first block
			
			res = oneBlockEcbDec(set, tmpDec, &tmpDecLen);
		       if(res != CONVERT_OK){
				return res;  
		 
		       } 
		
		       for(index = 0; index < BLOCKSIZE; index++){
				tmpDec[index] = tmpDec[index] ^ set -> iv[index];
			}		
		
		}
		
		
		
		else{ //after first block
			
			memset(tmpDec, 0x00, tmpDecLen);		

			res = oneBlockEcbDec(set, tmpDec, &tmpDecLen);
			if(res != CONVERT_OK){
				return res;	
			}
			
			for(index = 0; index < BLOCKSIZE; index++){
				tmpDec[index] = tmpDec[index] ^ xorOper[index];
			}
		}
		
		memset(xorOper, 0x00, xorOperLen);
		
		for(index = 0; index < 16; index++){

			*(outData + i + index) = tmpDec[index];
			
			xorOper[index] = set -> cryped_tmp[index];
		}

		*(outData + i + index) = '\0';

		memset(set -> cryped_tmp, 0x00, set -> crypedLen);  
		*outDataLen += tmpDecLen;
	
		i += 16;
	}

	res = paddingCut(paddingOper, outDataLen, padding, outData);
	if(res != CONVERT_OK){
		printf("paddingCut Err Code : %d\n",res);
		return res;
	}
	
	return CONVERT_OK;
}


int cfbEnc(setting_var* set, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen){

	if(inData == NULL) return ERR;
	if(set -> key == NULL) return ERR;

	int i = 0, j = 1;
	int index = 0;

	int tmp = 0;
	int res = 0;

	uint8_t tmpXor[BLOCKSIZE] = { 0x00, };
	uint32_t tmpXorLen = BLOCKSIZE;

	uint8_t plainTmp[BLOCKSIZE] = { 0x00, };
	
	uint8_t tmpEnc[BLOCKSIZE] = { 0x00, };
	uint32_t tmpEncLen = BLOCKSIZE;
	
	while(i < set -> totalEncLen){	
		
 		index = 0;

		res = padding(set,i, j, inData);
		if(res != CONVERT_OK){
			printf("pddingfunc Err Code : %d\n", res);
			return res;
		}

	


		if(i == 0){
			
			
			for(index = 0; index < BLOCKSIZE; index++){
			 
				plainTmp[index] = set -> plain_tmp[index];
				set -> plain_tmp[index] = set -> iv[index];
			}
			
			res = oneBlockEcbEnc(set, tmpEnc, &tmpEncLen);
			if(res != CONVERT_OK){
				printf("oneBlockCbcEnc Err Code : %d\n", res);
				return res;
			}	
			
			memset(set -> plain_tmp, 0x00, set -> plainLen);

			for(index = 0; index < BLOCKSIZE; index++){
				set -> plain_tmp[index] = plainTmp[index] ^ tmpEnc[index];
				tmpXor[index] = set -> plain_tmp[index];
			}		
		
		
		
		
		}else{
					
			for(index = 0; index < BLOCKSIZE; index++){
				plainTmp[index] = set -> plain_tmp[index];
				
				set -> plain_tmp[index] = tmpXor[index];
			}
				
			set -> plainLen = tmpXorLen;

			res = oneBlockEcbEnc(set,tmpEnc, &tmpEncLen);
			if(res != CONVERT_OK){
				printf("oneBlockCbcEnc Err Code : %d\n", res);
				return res;
			}
			
			memset(tmpXor, 0x00, tmpXorLen);
			
			for(index = 0; index < BLOCKSIZE; index++){
				tmpXor[index] = plainTmp[index] ^ tmpEnc[index];
			}
		}
		
		
		
		
		for(index = 0; index < tmpEncLen; index++){	
			*(outData + i + index) = tmpXor[index];
		}

		i+= BLOCKSIZE;
		j++;
	
		memset(set -> plain_tmp, 0, set -> plainLen);
		*outDataLen += tmpEncLen; 

	}
	
	memset(tmpEnc, 0x00, tmpEncLen);
	
	*(outData + *outDataLen + 1) = '\0';
	
	 return CONVERT_OK;
}

int cfbDec(setting_var* set, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen){
	
	if(inData == NULL) return ERR;
	if(set -> key == NULL) return ERR;
		
	uint8_t xorOper[16] = { 0x00, };
	uint32_t xorOperLen = 16;
	
	int i = 0, j = 1;
	int index = 0;
	
	int res = 0;
	
	int padding = 0;
	uint32_t paddingOper = 0;



	uint8_t tmpDec[BLOCKSIZE] = { 0x00, };
	uint32_t tmpDecLen = BLOCKSIZE;
	


	while(i < inDataLen){
		
		index = 0;

		for(; index < 16; index++){
			set -> cryped_tmp[index] = *(inData + i + index);
		}




		if(i == 0){ //first block
	
			for(index = 0; index < BLOCKSIZE; index++){
				set -> plain_tmp[index] = set -> iv[index];
			}

			res = oneBlockEcbEnc(set, tmpDec, &tmpDecLen);
		       if(res != CONVERT_OK){
				return res;  
		       } 	       
			for(index = 0; index < BLOCKSIZE; index++){
				
				tmpDec[index] = tmpDec[index] ^ set -> cryped_tmp[index];
			}
		}
		

		
		 

		
		else{ //after first block
			
			memset(tmpDec, 0x00, tmpDecLen);		

			res = oneBlockEcbEnc(set, tmpDec, &tmpDecLen);
			if(res != CONVERT_OK){
				return res;	
			}
			
			for(index = 0; index < BLOCKSIZE; index++){
				tmpDec[index] = set->cryped_tmp[index] ^ tmpDec[index];
			}
		
		}
		
		
		
		memset(set -> plain_tmp, 0x00, set -> plainLen);
		
		for(index = 0; index < BLOCKSIZE; index++){

			*(outData + i + index) = tmpDec[index];
			
			set -> plain_tmp[index] = set -> cryped_tmp[index];
		}

		*(outData + i + index) = '\0';

		memset(set -> cryped_tmp, 0x00, set -> crypedLen);  
		
		*outDataLen += tmpDecLen;
	
		i += 16;
	}

	res = paddingCut(paddingOper, outDataLen, padding, outData);
	if(res != CONVERT_OK){
		printf("paddingCut Err Code : %d\n",res);
		return res;
	}

	return CONVERT_OK;

}

int ofbEnc(setting_var* set, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen){
	
	if(inData == NULL) return ERR;
	if(set -> key == NULL) return ERR;

	uint8_t plainTmp[BLOCKSIZE] = { 0x00, };
	uint32_t plainTmpLen = BLOCKSIZE;

	uint8_t tmpXor[BLOCKSIZE] = { 0x00, };
	uint32_t tmpXorLen = BLOCKSIZE;

	uint8_t tmpEnc[BLOCKSIZE] = { 0x00, };
	uint32_t tmpEncLen = BLOCKSIZE;

	int i = 0, j = 1;
	int index = 0;

	int tmp = 0;
	int res = 0;
	
	while(i < set -> totalEncLen){	
		
 		index = 0;
			
		res = padding(set,i, j, inData);
		if(res != CONVERT_OK){
			printf("pddingfunc Err Code : %d\n", res);
			return res;
		}

		if(i == 0){
				
			for(index = 0; index < BLOCKSIZE; index++){
				plainTmp[index] = set -> plain_tmp[index];
				set -> plain_tmp[index] = set -> iv[index];
			}	



			res = oneBlockEcbEnc(set, tmpEnc, &tmpEncLen);
			if(res != CONVERT_OK){
				printf("oneBlockCbcEnc Err Code : %d\n", res);
				return res;
			}	
			


			memset(set -> plain_tmp, 0x00, set -> plainLen);

			for(index = 0; index < BLOCKSIZE; index++){

				set -> plain_tmp[index] = plainTmp[index] ^ tmpEnc[index];
				tmpXor[index] = set -> plain_tmp[index];
			}
		
			for(index = 0; index < tmpEncLen; index++){
			
				*(outData + i + index) = tmpXor[index];
			}

		}
		
		
		else{
						
			for(index = 0; index < BLOCKSIZE; index++){
				plainTmp[index] = set -> plain_tmp[index];
				set -> plain_tmp[index] = tmpEnc[index];		
			}
			
			memset(tmpEnc , 0x00, tmpEncLen);
	
			res = oneBlockEcbEnc(set, tmpEnc, &tmpEncLen);
			if(res != CONVERT_OK){
				printf("oneBlockCbcEnc Err Code : %d\n", res);
				return res;
			}

			
			for(index = 0; index < BLOCKSIZE; index++){
								
				tmpXor[index] = plainTmp[index] ^ tmpEnc[index];
			}
			
			for(index = 0; index < tmpEncLen; index++){
			
				*(outData + i + index) = tmpXor[index];
			}
		}
		
			
		i+= BLOCKSIZE;
		j++;
	
		memset(set -> plain_tmp, 0, set -> plainLen);
		*outDataLen += tmpEncLen; 

	}	
		
	
	*(outData + *outDataLen + 1) = '\0';
	
	 return CONVERT_OK;
}

int ofbDec(setting_var* set,  uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen){

	if(inData == NULL) return ERR;
	if(set -> key == NULL) return ERR;		
	
	uint8_t crypedTmp[BLOCKSIZE] = { 0x00, };
	uint32_t crypedTmpLen = BLOCKSIZE;

	int padding = 0;
	
	int i = 0, j = 1;
	int index = 0;
	
	int res = 0;
	uint32_t paddingOper = 0;

	uint8_t tmpDec[BLOCKSIZE];
	uint32_t tmpDecLen = BLOCKSIZE;

	while(i < inDataLen){
		
		index = 0;
		
		for(; index < BLOCKSIZE; index++){
			
			set->cryped_tmp[index] = *(inData + i + index);
			
		}

		
		
		
		if( i == 0){ //first block

			for(index = 0; index < BLOCKSIZE; index++){
				set -> plain_tmp[index] = set -> iv[index];
			}	


			res = oneBlockEcbEnc(set, tmpDec, &tmpDecLen);
		       if(res != CONVERT_OK){
				return res;  
		       }   
			for(index = 0; index < BLOCKSIZE; index++){
				
				tmpDec[index] = tmpDec[index] ^ set -> cryped_tmp[index];
				
			}
		       	
			for(index = 0; index < tmpDecLen; index++){

				*(outData + i + index) =  tmpDec[index];
			
			}

			*outDataLen += tmpDecLen;	
		}
		


		else{ //after first block
						
			for(index = 0; index < BLOCKSIZE; index++){

				set -> plain_tmp[index] = tmpDec[index];	
			
			}

			memset(tmpDec, 0x00, tmpDecLen);
		
			res = oneBlockEcbEnc(set, tmpDec, &tmpDecLen);
			if(res != CONVERT_OK){
				return res;	
			}
			memset(tmpDec, 0x00, tmpDecLen);

			for(index = 0; index < BLOCKSIZE; index++){
				tmpDec[index] = set -> cryped_tmp[index] ^ tmpDec[index];
			}
			
			for(index = 0; index < tmpDecLen; index++){
			
				*(outData + i + index) = tmpDec[index];

			}
	
			*outDataLen += tmpDecLen;

		}




		*(outData + i + index) = '\0';

		memset(set -> cryped_tmp, 0x00, set -> crypedLen);  
			
		i += 16;
	}
	
	res = paddingCut(paddingOper, outDataLen, padding, outData);
	if(res != CONVERT_OK){
		printf("paddingCut Err Code : %d\n",res);
		return res;
	}

	return CONVERT_OK;
}


int oneBlockEcbEnc(setting_var* set,uint8_t* tmpEnc, uint32_t* tmpEncLen){

	if(set -> plain_tmp == NULL) return ERR;
	if(set -> key == NULL) return ERR;
	
	int res = 0;	

	EDGE_CIPHER_PARAMETERS param;
	memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));

	param.m_mode = EDGE_CIPHER_MODE_CBC;
	param.m_padding = EDGE_CIPHER_PADDING_NONE;
	param.m_modeparam.m_ivlength = 16; 

	res = edge_enc(set -> cipherId, set-> key, set-> keyLen, &param, set -> plain_tmp, set -> plainLen, tmpEnc, tmpEncLen);
	if(res != 0){
		printf("edge_enc Err Code : %d\n", res);
		return res;
	}

	return CONVERT_OK;
}

int oneBlockEcbDec(setting_var* set, uint8_t* tmpDec, uint32_t* tmpDecLen){

	if(set -> cryped_tmp == NULL) return ERR;
	if(set -> key == NULL) return ERR;
	
	int res = 0;
	
	EDGE_CIPHER_PARAMETERS param;
	memset(&param, 0, sizeof(EDGE_CIPHER_PARAMETERS));

	param.m_mode = EDGE_CIPHER_MODE_CBC; 
	param.m_padding = EDGE_CIPHER_PADDING_NONE; 
	param.m_modeparam.m_ivlength = 16; 
	
	res = edge_dec(set -> cipherId, set-> key, set-> keyLen, &param, set -> cryped_tmp, set -> crypedLen, tmpDec,  tmpDecLen);
	if(res != 0){
		printf("edge_dec Err Code : %d\n", res);
		return res;
	}
	
	memset(param.m_modeparam.m_iv, 0x00, param.m_modeparam.m_ivlength);

	return CONVERT_OK;
}



int ms_enc(setting_var* set, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen){
		
	int res = 0;
	
	switch(set->m_mode){

		case CBC:
			
			res = cbcEnc(set, inData, inDataLen, outData, outDataLen);
			if(res != CONVERT_OK){
				printf("cbcEnc Err Code : %d\n", res);
				return res;
			}
			
			break;

		case CFB:
			res = cfbEnc(set, inData, inDataLen, outData, outDataLen);
			if(res != CONVERT_OK){
				printf("cbcEnc Err Code : %d\n", res);
				return res;
			}

			break;

		case OFB:
			res = ofbEnc(set, inData, inDataLen, outData, outDataLen);
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

int ms_dec(setting_var* set, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen){
	
	int res = 0;
	
	switch(set -> m_mode){

		case CBC:	
			res = cbcDec(set, inData, inDataLen, outData, outDataLen);
			if(res != CONVERT_OK){
				printf("cbcEnc Err Code : %d\n", res);
				return res;
			}
			
			break;

		case CFB:
			res = cfbDec(set, inData, inDataLen, outData, outDataLen);
			if(res != CONVERT_OK){
				printf("cbcEnc Err Code : %d\n", res);
				return res;
			}
			
			break;

		case OFB:
			res = ofbDec(set, inData, inDataLen, outData, outDataLen);
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


