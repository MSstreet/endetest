#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "edge_crypto.h"

#define			BLOCKSIZE	16

#define			CONVERT_OK	1

#define			ERR		10000


typedef struct _setting_var{

	uint8_t plain_tmp[BLOCKSIZE];
	uint32_t plainLen;

	uint8_t cryped_tmp[BLOCKSIZE];
	uint32_t crypedLen;

	uint8_t iv[BLOCKSIZE];
	uint32_t ivLen;
	
	uint8_t tmpEnc[BLOCKSIZE];
	uint32_t tmpEncLen;

	uint8_t tmpDec[BLOCKSIZE];
	uint32_t tmpDecLen;
	
	uint32_t paddingNum;
	
	int blockNum;
	int totalEncLen;

}setting_var;


typedef struct _test_param_mode{
	
	uint8_t m_iv[32];
	uint32_t m_ivlength;
	uint32_t m_modesize;

}test_param_mode;


typedef struct _test_param{
	
	int m_mode;
	int m_padding;
	test_param_mode m_modeparam;

}test_param;



int settingVarFunc(setting_var* set, test_param* param, uint32_t inDataLen);



int cbcEnc(uint32_t cipherId, test_param* param, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen);

int cbcDec(uint32_t cipherId, test_param* param, uint8_t* inData,uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen);

int cfbDec(uint32_t cipherId, test_param* param, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen);

int cfbEnc(uint32_t cipherId,  test_param* param, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen);

int ofbDec(uint32_t cipherId, test_param* param, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen);

int ofbEnc(uint32_t cipherId,  test_param* param, uint8_t* inData, uint32_t inDataLen, uint8_t* outData, uint32_t* outDataLen, uint8_t* key, uint32_t keyLen);



int oneBlockEcbEnc(uint32_t cipherId, setting_var* set, uint8_t* key, uint32_t keyLen);

int oneBlockEcbDec(uint32_t cipherId, setting_var* set, uint8_t* key, uint32_t keyLen);


