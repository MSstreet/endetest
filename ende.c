#include <stdio.h>
#include "ende.h"
#include "edge_crypto.h"

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

	printf("plainLen : %d\n", set.plainLen);
	printf("ivLen : %d\n", set.ivLen);
	printf("tmpEncLen : %d\n", set.tmpEncLen);
	printf("paddingNum : %d\n", set.paddingNum);
	printf("blockNum : %d\n", set.blockNum);
	printf("totalEncLen : %d\n", set.totalEncLen);

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

			
		}else{
			
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
			//memset(set.tmpEnc , 0x00, set.tmpEncLen);
			
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
	
	uint8_t crypedTmp[16] = { 0x00, };
	uint32_t crypedLen = 16;
	
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
			//memset(tmpEnc1, 0x00, tmpEncLen1);
			
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
			
			//memset(tmpXor, 0x00, tmpXorLen);
			//memset(tmpEnc, 0x00, tmpEncLen);


			for(index = 0; index < BLOCKSIZE; index++){
				//tmpEnc[index] = tmpEnc1[index];
				
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


	//memset(tmpEnc, 0x00, tmpEncLen);

	//printf("outDataLen at cbcEncfunc : %d\n", *outDataLen);
	
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
/*
	uint8_t cryped_tmp[BLOCKSIZE] = { 0x00, };
	uint32_t crypedLen = BLOCKSIZE;

	uint8_t iv[BLOCKSIZE] = { 0x00, };
	uint32_t ivLen = param->m_modeparam.m_ivlength;
		
	uint8_t tmpXor[BLOCKSIZE] = { 0x00, };
	uint32_t tmpXorLen = BLOCKSIZE;

	uint8_t tmpDec[BLOCKSIZE] = { 0x00, };
	uint32_t tmpDecLen = BLOCKSIZE;

	uint8_t tmpDec1[BLOCKSIZE] = { 0x00, };
	uint32_t tmpDecLen1 = BLOCKSIZE;

	uint8_t test[BLOCKSIZE] = { 0x00, };
	uint32_t testLen = BLOCKSIZE;
	*/
	
	//memcpy(iv, param->m_modeparam.m_iv, ivLen); 

	//printf("EncDataLen at cbcDecfunc : %d\n", inDataLen);

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
			
			//memset(tmpDec, 0x00, tmpDecLen);		
			//memset(tmpDec1, 0x00, tmpDecLen1);
			
			for(index = 0; index < BLOCKSIZE; index++){

				set.plain_tmp[index] = set.tmpEnc[index];	
			
			}

			memset(set.tmpEnc, 0x00, set.tmpEncLen);
		
			res = oneBlockEcbEnc(cipherId ,&set, key, keyLen);
			if(res != CONVERT_OK){
				return res;	
			}
			
			//memset(tmpXor, 0x00, tmpXorLen);
			memset(set.tmpDec, 0x00, set.tmpDecLen);

			for(index = 0; index < BLOCKSIZE; index++){
			//	tmpDec[index] = tmpDec1[index];
				set.tmpDec[index] = set.cryped_tmp[index] ^ set.tmpEnc[index];
			}
			
			for(index = 0; index < set.tmpEncLen; index++){
			
				*(outData + i + index) = set.tmpDec[index];

			}
	
			*outDataLen += set.tmpEncLen;

		}
	
	
		//memset(xorOper, 0x00, xorOperLen);
		/*
		for(index = 0; index < 16; index++){

			*(outData + i + index) = tmpDec[index];
			
			xorOper[index] = cryped_tmp[index];
		}*/

		
		*(outData + i + index) = '\0';

		memset(set.cryped_tmp, 0x00, set.crypedLen);  
		//*outDataLen += tmpDecLen;
	
		i += 16;
	}
		
	
	paddingOper = *outDataLen - 1;

	printf("paddingOper : %d\n", paddingOper);

	padding = *(outData + paddingOper);

	printf("padding : %d\n", padding);
	printf("OutDataLen : %d\n", *outDataLen);

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



