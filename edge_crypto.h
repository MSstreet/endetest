/**
 * @section Encoding
 * UTF-8
 *
 * @section License
 *
 * @brief 암호화 라이브러리
 * @file edge_crypto.h
 * @version 4.0
 * @author warmstar (mkshin@secucen.com)
 * @copyright secucen
 * @brief
 */

#ifndef __EDGE_CRYPTO_H__
#define __EDGE_CRYPTO_H__
#include "edge_crypto_global.h"
#include "edge_crypto_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * cmvp check
 */

/**
 * @defgroup cmvp CMVP 기능
 * @ingroup cmvp
 * @brief CMVP에 필요한 기능 제공 
 *  -# 초기화, 메모리 해제 
 *  -# 모드 변경 기능 (검증 모드, 비검증 모드)
 *  -# 상태 확인 기능 (현 상태 정보 리턴)
 *  -# 랜덤 함수 
 *   - 랜덤 함수는 내부적으로 해쉬 기반 난수 발생기를 사용하고 있으며 모드 변경시 난수 발생기 내부 정보는 초기화 된다. 
 */

/**
 ** @ingroup cmvp
 ** @anchor EDGE_CRYPTO_STATUS
 ** @brief edge_crypto 라이브러리 상태 정보
 **/
typedef enum {
    EDGE_CRYPTO_STATUS_NOT_INITIALIZED = 0,     /**< 초기화 전 상태 */
    EDGE_CRYPTO_STATUS_INIT_SELFTEST,           /**< 동작 전 자가 시험 상태 */
    EDGE_CRYPTO_STATUS_CMVP,                    /**< 검증 대상 동작 상태 */
    EDGE_CRYPTO_STATUS_CONDITIONAL_SELFTEST,    /**< 조건부 자가 시험 상태 */
    EDGE_CRYPTO_STATUS_NORMAL,                  /**< 비검증 대상 동작 상태 */
    EDGE_CRYPTO_STATUS_ERROR                    /**< 심각한 오류 상태 */
} EDGE_CRYPTO_STATUS;


/**
 * @ingroup cmvp
 * @anchor edge_crypto_get_version
 * @brief edge_crypto 모듈의 버전정보 문자열을 리턴한다. 
 * @return const char *  버전 정보 문자열
 */
EDGE_EXPORT const char *    edge_crypto_get_version             (void);
typedef     const char *    (*fp_edge_crypto_get_version)       (void);

/**
 * @ingroup cmvp 
 * @anchor edge_random_byte
 * @see edge_random_bit
 * @brief 요청한 바이트 수만큼 랜덤 값을 가져온다.
 * @param p_buffer [out] uint8_t * 랜덤 값을 받아올 버퍼의 주소
 * @param p_reqSize [in] uint32_t 랜덤 요청 바이트 길이
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */
EDGE_EXPORT int             edge_random_byte                    (uint8_t * p_buffer, uint32_t p_reqSize);
typedef     int             (*fp_edge_random_byte)              (uint8_t *, uint32_t);

/**
 * @ingroup cmvp 
 * @anchor edge_crypto_init
 * @brief edge crypto CMVP 초기화 함수로 crypto 모듈 사용 전에 필히 실행애 주어야 한다. 
 *        서명값 데이터 파일이 library와 별도로 존재하는 경우 지정된 경로에 서명값 데이터 파일이 존재해야 한다.
 * @param p_signPath [in] uint8_t * 서명 파일 경로 (Mac, Android, iOS 운영체제만 해당) \n
 *        Mac, Android, iOS 외 NULL 입력. 
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */
EDGE_EXPORT int             edge_crypto_init                    (uint8_t * p_signPath);
typedef     int             (*fp_edge_crypto_init)              (uint8_t *);

/**
 * @ingroup cmvp 
 * @anchor edge_crypto_final
 * @brief edge crypto CMVP 종료 함수로 내부적으로 사용한 메모리를 해제한다.
 * @return
 */
EDGE_EXPORT void            edge_crypto_final                   (void);
typedef     void            (*fp_edge_crypto_final)             (void);

/**
 * @ingroup cmvp 
 * @anchor edge_crypto_change_mode
 * @brief edge_crypto 모듈의 운영모드를 검증 대상 동작 모드에서 비검증 대상 동작 모드로 변경한다.
 * @remark edge_crypto는 검증 모드에서 비검증 모드로 전환 후 다시 검증 모드로 돌아올 수 없다.
 * @return void
 */
EDGE_EXPORT int             edge_crypto_change_mode             (void);
typedef     int             (*fp_edge_crypto_change_mode)       (void);

/**
 * @ingroup cmvp
 * @anchor edge_crypto_get_status
 * @brief edge_crypto 모듈의 현재 상태 정보를 가져 온다. 
 * @see EDGE_CRYPTO_STATUS
 * @return int EDGE_CRYPTO_STATUS 정보를 리턴한다.
 */
EDGE_EXPORT int             edge_crypto_get_status              (void); 
typedef     int             (*fp_edge_crypto_get_status)        (void); 

/**
 * @ingroup cmvp
 * @anchor edge_crypto_zeroize
 * @brief edge_crypto_zeroize 입력 받은 버퍼를 zero화 할때 사용한다. (대칭키 삭제 등)
 * @param void * p_data 제로화 하고자 하는 메모리 주소
 * @param uint32_t p_dataSize 제로화 대상 길이 
 * @return void
 */
EDGE_EXPORT void            edge_crypto_zeroize                 (void * p_data, uint32_t p_dataSize);
typedef     void            (*fp_edge_crypto_zeroize)           (void *, uint32_t);

/**
 * @ingroup cmvp
 * @anchor edge_crypto_cmvp_selftest
 * @brief 엔트로피 테스트, 무결성 검증, 모든 검증대상 알고리즘 자가테스트를 수행하는 사함수이다. 
 *        이 함수 실행시 다른 스레드의 입출력을 막는다. 
 * @param p_signPath [in] uint8_t * 서명 파일 경로 (Mac, Android, iOS 운영체제만 해당) \n
 *        Mac, Android, iOS 외 NULL 입력. 
 * @return EDGE_ERR_SUCCESS 성공 \n 그외 실페에 따른 오류 코드
 */
EDGE_EXPORT int             edge_crypto_cmvp_selftest           (uint8_t* p_signPath);
typedef     int             (*fp_edge_crypto_cmvp_selftest)     (uint8_t*);


#define EDGE_CIPHER_BLOCK_SIZE_64                           8
#define EDGE_CIPHER_BLOCK_SIZE_128                          16
#define EDGE_CIPHER_BLOCK_SIZE_MAX                          32

#define EDGE_CIPHER_IV_LENGTH_64                            8
#define EDGE_CIPHER_IV_LENGTH_128                           16
/* cipher algorithm */
/**
 * @defgroup blockcipher 블럭 암호(Block Cipher)
 * @ingroup blockcipher
 * @brief 블럭 암호(대칭키 암호) 알고리즘 지원 API
 */

#define EDGE_CIPHER                                         100                   
#define EDGE_CIPHER_ID_AES128                               (EDGE_CIPHER + 11)
#define EDGE_CIPHER_ID_AES192                               (EDGE_CIPHER + 12)
#define EDGE_CIPHER_ID_AES256                               (EDGE_CIPHER + 13)
#define EDGE_CIPHER_ID_SEED128                              (EDGE_CIPHER + 21)
#define EDGE_CIPHER_ID_SEED256                              (EDGE_CIPHER + 22)
#define EDGE_CIPHER_ID_ARIA128                              (EDGE_CIPHER + 31)
#define EDGE_CIPHER_ID_ARIA192                              (EDGE_CIPHER + 32)
#define EDGE_CIPHER_ID_ARIA256                              (EDGE_CIPHER + 33)
#define EDGE_CIPHER_ID_HIGHT                                (EDGE_CIPHER + 40)
#define EDGE_CIPHER_ID_LEA128                               (EDGE_CIPHER + 51)
#define EDGE_CIPHER_ID_LEA192                               (EDGE_CIPHER + 52)
#define EDGE_CIPHER_ID_LEA256                               (EDGE_CIPHER + 53)
#define EDGE_CIPHER_ID_UNKNOWN                              (EDGE_CIPHER + 90)

/**
 * @ingroup blockcipher
 * @anchor EDGE_CIPHER_MODE
 * @brief블럭 암호(대칭키 암호) 운영모드 ID */
typedef enum {
    EDGE_CIPHER_MODE_ECB                                    = 1,    /**< ECB 운영 모드 (복호화만 가능) */
    EDGE_CIPHER_MODE_CBC                                    ,       /**< CBC 운영 모드 */
    EDGE_CIPHER_MODE_CFB                                    ,       /**< CFB 운영 모드 */
    EDGE_CIPHER_MODE_OFB                                    ,       /**< OFB 운영 모드 */
    EDGE_CIPHER_MODE_CTR                                    ,       /**< CTR 운영 모드 */
    EDGE_CIPHER_MODE_UNKNOWN
} EDGE_CIPHER_MODE;

/**
 * @ingroup blockcipher
 * @anchor EDGE_CIPHER_PADDING
 * @brief  블럭 암호(대칭키 암호) 패딩 ID
 */
typedef enum {
    EDGE_CIPHER_PADDING_NONE                                = 1,    /**< 패딩을 사용하지 않는다. */
    EDGE_CIPHER_PADDING_ZERO                                ,       /**< ZERO 패딩 */
    EDGE_CIPHER_PADDING_PKCS5                               ,       /**< PKCS5 패딩 */
    EDGE_CIPHER_PADDING_ANSI_x9_23                          ,       /**< ANSI_X9_23 패팅 */
    EDGE_CIPHER_PADDING_UNKNOWN
} EDGE_CIPHER_PADDING;

#define EDGE_CIPHER_IV_LENGTH_MAX                           32      /**< 블럭 암호화 초기화 벡터 최대 값 */
#define EDGE_CIPHER_KEY_LENGTH_MIN                          8       /**< 블럭 암호화 키 길이 최소 값 */
#define EDGE_CIPHER_KEY_LENGTH_MAX                          32      /**< 블럭 암호화 키 길이 최대 값 */

/**
 * @ingroup blockcipher
 * @struct EDGE_CIPHER_MODE_PARAMETERS
 * @anchor EDGE_CIPHER_MODE_PARAMETERS
 * @brief 블록알고리즘 운용모드(CBC,OFB,CFB,CTR)별로 필요한 세부사항에 대한 설정 구조체. 
 */
typedef struct {
    uint8_t     m_iv[EDGE_CIPHER_IV_LENGTH_MAX];    /**< 초기화 벡터. */
    uint32_t    m_ivlength;                         /**< 초기화 벡터의 길이. (단위:byte) */
    uint32_t    m_modesize;                         /**< CFB, OFB, CTR모드의 경우 해당 모드의 길이. (단위:byte)
                                                         - OFB, CFB : 해당 모드의 길이 (0일경우 해당 블럭 사이즈 적용)
                                                         - CTR : CTR모드에서 사용될 고정 랜덤 의 길이*/
} EDGE_CIPHER_MODE_PARAMETERS;

/**
 * @ingroup blockcipher
 * @struct EDGE_CIPHER_PARAMETERS
 * @anchor EDGE_CIPHER_PARAMETERS
 * @brief 블록알고리즘별로 필요한 세부사항에 대한 설정 구조체.  */
typedef struct {
    int                                 m_mode;         /**< 운영 모드 설정. EDGE_CIPHER_MODE */
    int                                 m_padding;      /**< 패딩 방식 설정. EDGE_CIPHER_PADDING @see EDGE_CIPHER_PADDING*/
    EDGE_CIPHER_MODE_PARAMETERS         m_modeparam;    /**< @see EDGE_CIPHER_MODE_PARAMETERS */
} EDGE_CIPHER_PARAMETERS;

/**
 * @ingroup blockcipher
 * @anchor edge_enc
 * @brief 대칭키 암호문을 생성하기 위한 함수
 * @param p_key [in] uint8_t * 암호 알고리즘에 사용되는 대칭 키.
 * @param p_keyLen [in] uint32_t 대칭 키의 길이.
 * @param p_cipherId [in] int 암호화에 사용할 알고리즘
 * @param p_param [in] EDGE_CIPHER_PARAMETERS * 암호 알고리즘에 적용할 세부 설정.
 * @param p_input [in] uint8_t * 암호화 대상 평문.
 * @param p_inputLen [in] uint32_t 암호화 대상 평문의 길이.
 * @param p_output [out] uint8_t * 암호화된 암호문.
 * @param p_outputLen [out] uint32_t * 암호문의 길이.
* @brief <ul><li><pre>
 * 키 길이 제한 - SEED  : 16 byte</li>
 *                HIGHT : 16 byte
 *                ARIA  : 16 / 24 / 32 byte
 *                LEA   : 16 / 24 / 32 byte
 * <li>
 * iv 길이 제한 - SEED  : 16 byte</li>
 *                HIGHT : 8 byte
 *                ARIA  : 16 byte
 *                LEA   : 16 byte</pre></ul>
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */
EDGE_EXPORT int             edge_enc                        (int p_cipherId,
                                                             uint8_t * p_key, uint32_t p_keyLen,
                                                             EDGE_CIPHER_PARAMETERS * p_param,
                                                             uint8_t * p_input, uint32_t p_inputLen,
                                                             uint8_t * p_output, uint32_t * p_outputLen);
typedef     int             (*fp_edge_enc)                  (int,
                                                             uint8_t *, uint32_t,
                                                             EDGE_CIPHER_PARAMETERS *,
                                                             uint8_t *, uint32_t,
                                                             uint8_t *, uint32_t *);

/**
 * @ingroup blockcipher
 * @anchor edge_dec
 * @brief 대칭키 암호문을 복호화하기 위한 함수
 * @param p_key [in] uint8_t * 암호 알고리즘에 사용되는 대칭 키.
 * @param p_keyLen [in] uint32_t 대팅 키의 길이.
 * @param p_cipherId [in] int 암호화에 사용할 알고리즘
 * @param p_param [in] EDGE_CIPHER_PARAMETERS * 암호 알고리즘에 적용할 세부 설정.
 * @param p_input [in] uint8_t * 암호화된 암호문.
 * @param p_inputLen [in] uint32_t 암호문의 길이.
 * @param p_output [out] uint8_t * 암호화 대상 평문. (input 데이터의 길이보다 크거나 같아야 한다)
 * @param p_outputLen [out] uint32_t * 암호화 대상 평문의 길이.
* @brief <ul><li><pre>
 * 키 길이 제한 - SEED  : 16 byte</li>
 *                HIGHT : 16 byte
 *                ARIA  : 16 / 24 / 32 byte
 *                LEA   : 16 / 24 / 32 byte
 * <li>
 * iv 길이 제한 - SEED  : 16 byte</li>
 *                HIGHT : 8 byte
 *                ARIA  : 16 byte
 *                LEA   : 16 byte</pre></ul>
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */
EDGE_EXPORT int             edge_dec                        (int p_cipherId,
                                                             uint8_t * p_key, uint32_t p_keyLen,
                                                             EDGE_CIPHER_PARAMETERS * p_param,
                                                             uint8_t * p_input, uint32_t p_inputLen,
                                                             uint8_t * p_output, uint32_t * p_outputLen);
typedef     int             (*fp_edge_dec)                  (int,
                                                             uint8_t *, uint32_t,
                                                             EDGE_CIPHER_PARAMETERS *,
                                                             uint8_t *, uint32_t,
                                                             uint8_t *, uint32_t *);

typedef struct _edge_cipher_ctx_ EDGE_CIPHER_CTX;

/**
 * @ingroup blockcipher
 * @anchor edge_ctx_new
 * @brief 대칭키 암/복호화에 사용되는 context 생성 (init/update/final에 사용)
 *        사용 후 edge_ctx_free로 메모리 해제해 주어야 한다. 
 *        ini/update/final 사용이 끝난 후 다시 사용할 경우 필히 edge_ctx_reset을 호출해서 초기화 해주어야 한다.
 * @see edge_ctx_free
 * @see edge_ctx_reset
 * @return EDGE_CIPHER_CTX * 내부적인 상태 정보를 저장하고 있는 구조체의 주소. \n
 *         NULL 메모리 할당 실패. 
 */
EDGE_EXPORT EDGE_CIPHER_CTX *  edge_ctx_new                 (void);
typedef     EDGE_CIPHER_CTX *  (*fp_edge_ctx_new)           (void);

/**
 * @ingroup blockcipher
 * @anchor edge_ctx_reset
 * @brief 대칭키 암/복호화에서 할당된 context 메모리 초기화 함수.
 * @param p_context [in] EDGE_CIPHER_CTX * 대칭키 암/복호화에 사용되는 Context 구조체의 주소
 * @see edge_ctx_new
 * @see edge_ctx_free
 * @return 
 */
EDGE_EXPORT void        edge_ctx_reset                      (EDGE_CIPHER_CTX * p_context);
typedef     void        (*fp_edge_ctx_reset)                (EDGE_CIPHER_CTX *);

/**
 * @ingroup blockcipher
 * @anchor edge_ctx_free
 * @brief 대칭키 암/복호화에서 할당된 context 메모리 해제 함수.
 * @param p_context [in] EDGE_CIPHER_CTX * 대칭키 암/복호화에 사용되는 Context 구조체의 주소
 * @see edge_ctx_new
 * @see edge_ctx_reset
 * @return 
 */
EDGE_EXPORT void        edge_ctx_free                       (EDGE_CIPHER_CTX * p_context);
typedef     void        (*fp_edge_ctx_free)                 (EDGE_CIPHER_CTX *);

/**
 * @ingroup blockcipher
 * @anchor edge_enc_init
 * @brief 대칭키 암호문을 생성하기 위한 초기화 함수.
 * @param p_context [in] EDGE_CIPHER_CTX * 내부적인 상태 관리를 위한 context edge_ctx_new로 생성한다. 
 * @param p_key [in] uint8_t * 암호 알고리즘에 사용되는 대칭 키.
 * @param p_keyLen [in] uint32_t 대칭 키의 길이.
 * @param p_cipherId [in] int 암호화에 사용할 알고리즘
 * @param p_param [in] EDGE_CIPHER_PARAMETERS * 암호 알고리즘에 적용할 세부 설정.
 * @see edge_ctx_new
 * @see EDGE_CIPHER_PARAMETERS
 * @see edge_enc_update
 * @see edge_enc_final
 * @brief <ul><li><pre>
 * 키 길이 제한 - SEED  : 16 byte</li>
 *                HIGHT : 16 byte
 *                ARIA  : 16 / 24 / 32 byte
 *                LEA   : 16 / 24 / 32 byte
 * <li>
 * iv 길이 제한 - SEED  : 16 byte</li>
 *                HIGHT : 8 byte
 *                ARIA  : 16 byte
 *                LEA   : 16 byte</pre></ul>
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */
EDGE_EXPORT int         edge_enc_init                       (EDGE_CIPHER_CTX * p_context,
                                                             const int p_cipherId,
                                                             uint8_t * p_key, uint32_t p_keyLen,
                                                             const EDGE_CIPHER_PARAMETERS * p_param);
typedef     int         (*fp_edge_enc_init)                 (EDGE_CIPHER_CTX *,
                                                             const int,
                                                             uint8_t *, uint32_t,
                                                             const EDGE_CIPHER_PARAMETERS *);

/**
 * @ingroup blockcipher
 * @anchor edge_enc_update
 * @brief 대칭키 암호문을 생성하기 위한 데이터 입력 함수.
 * @param p_context [in] EDGE_CIPHER_CTX * 내부적인 상태 관리를 위한 context edge_ctx_new로 생성한다. 
 * @param p_input [in] uint8_t * 암호화 대상 평문.
 * @param p_inputLen [in] uint32_t 암호화 대상 평문의 길이.
 * @param p_output [out] uint8_t * 암호화된 암호문.
 * @param p_outputLen [out] uint32_t * 암호문의 길이.
 * @see edge_ctx_new
 * @see edge_enc_init
 * @see edge_enc_final
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */
EDGE_EXPORT int         edge_enc_update                     (EDGE_CIPHER_CTX * p_context,
                                                             uint8_t * p_input, uint32_t p_inputLen,
                                                             uint8_t * p_output, uint32_t * p_outputLen);
typedef     int         (*fp_edge_enc_update)               (EDGE_CIPHER_CTX *,
                                                             uint8_t *, uint32_t,
                                                             uint8_t *, uint32_t *);

/**
 * @ingroup blockcipher
 * @anchor edge_enc_final
 * @brief 대칭키 암호문을 생성하기 위한 마지막 단계.
 * @param p_context [in] EDGE_CIPHER_CTX * 내부적인 상태 관리를 위한 context edge_ctx_new로 생성한다. 
 * @param p_output [out] uint8_t * 남아있는 마지막 암호문.
 * @param p_outputLen [out] uint32_t * 암호문의 길이.
 * @see edge_ctx_new
 * @see edge_enc_init
 * @see edge_enc_update
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */
EDGE_EXPORT int         edge_enc_final                      (EDGE_CIPHER_CTX * p_context,
                                                             uint8_t * p_output, uint32_t * p_outputLen);
typedef     int         (*fp_edge_enc_final)                (EDGE_CIPHER_CTX *,
                                                             uint8_t *, uint32_t *);


/**
 * @ingroup blockcipher
 * @anchor edge_dec_init
 * @brief 대칭키 암호문을 복호화 하기 위한 초기화 함수.
 * @param p_context [in] EDGE_CIPHER_CTX * 내부적인 상태 관리를 위한 context edge_ctx_new로 생성한다. 
 * @param p_key [in] uint8_t * 암호 알고리즘에 사용되는 대칭 키.
 * @param p_keyLen [in] uint32_t 대칭 키의 길이.
 * @param p_cipherId [in] int 암호화에 사용할 알고리즘
 * @param p_param [in] EDGE_CIPHER_PARAMETERS * 암호 알고리즘에 적용할 세부 설정.
 * @brief <ul><li><pre>
 * 키 길이 제한 - SEED  : 16 byte</li>
 *                HIGHT : 16 byte
 *                ARIA  : 16 / 24 / 32 byte
 *                LEA   : 16 / 24 / 32 byte
 * <li>
 * iv 길이 제한 - SEED  : 16 byte</li>
 *                HIGHT : 8 byte
 *                ARIA  : 16 byte
 *                LEA   : 16 byte</pre></ul>
 * @see edge_ctx_new
 * @see EDGE_CIPHER_PARAMETERS
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */
EDGE_EXPORT int         edge_dec_init                       (EDGE_CIPHER_CTX * p_context,
                                                             const int p_cipherId,
                                                             uint8_t * p_key,
                                                             uint32_t p_keyLen,
                                                             const EDGE_CIPHER_PARAMETERS * p_param);
typedef     int         (*fp_edge_dec_init)                 (EDGE_CIPHER_CTX *,
                                                             const int,
                                                             uint8_t *,
                                                             uint32_t,
                                                             const EDGE_CIPHER_PARAMETERS *);

/**
 * @ingroup blockcipher
 * @anchor edge_dec_update
 * @brief 대칭키 암호문을 생성하기 위한 데이터 입력 함수.
 * @param p_context [in] EDGE_CIPHER_CTX * 내부적인 상태 관리를 위한 context edge_ctx_new로 생성한다. 
 * @param p_input [in] uint8_t * 암호화된 암호문.
 * @param p_inputLen [in] uint32_t 암호문의 길이.
 * @param p_output [out] uint8_t * 암호화 대상 평문.
 * @param p_outputLen [out] uint32_t * 암호화 대상 평문의 길이.
 * @see edge_ctx_new
 * @see edge_dec_init
 * @see edge_dec_final
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */
EDGE_EXPORT int         edge_dec_update                     (EDGE_CIPHER_CTX * p_context,
                                                             uint8_t * p_input,
                                                             uint32_t p_inputLen,
                                                             uint8_t * p_output,
                                                             uint32_t * p_outputLen);
typedef     int         (*fp_edge_dec_update)               (EDGE_CIPHER_CTX *,
                                                             uint8_t *,
                                                             uint32_t,
                                                             uint8_t *,
                                                             uint32_t *);

/**
 * @ingroup blockcipher
 * @anchor edge_dec_final
 * @brief 대칭키 암호문을 복호화 하기 위한 마지막 단계.
 * @param p_context [in] EDGE_CIPHER_CTX * 내부적인 상태 관리를 위한 context edge_ctx_new로 생성한다. 
 * @param p_output [out] uint8_t * OFB,CFB,CTR 모드에서 패딩을 사용하지 않은 경우(스트림 암호화 모드)에만 사용된다. (패딩을 사용한경우 NULL 입력)
 *                                 남아있는 마지막 암호문.
 * @param p_outputLen [out] uint32_t * p_output을 사용한 경우 암호문의 길이.(p_output을 사용하지 않을 경우 NULL)
 * @param p_paddingLength [out] uint32_t * 패딩을 사용한 경우에만 사용되며 패딩된 길이를 전달한다. (패딩을 사용하지 않는 경우 NULL 입력)
 *                                        edge_dec_update 결과 값에 패딩 길이를 빼주어야 한다.
 * @remark - 스트림 암호화 모드에서 p_output의 버퍼는 최소 알고리즘 블럭 사이즈보다 같거나 커야한다.
 * @see edge_ctx_new
 * @see edge_enc_init
 * @see edge_enc_update
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */
EDGE_EXPORT int         edge_dec_final                      (EDGE_CIPHER_CTX * p_context,
                                                             uint8_t * p_output,
                                                             uint32_t * p_outputLen,
                                                             uint32_t * p_paddingLength);
typedef     int         (*fp_edge_dec_final)                (EDGE_CIPHER_CTX *,
                                                             uint8_t *,
                                                             uint32_t *,
                                                             uint32_t *);


/**
 * @defgroup authcrypto_gcm 메시지 인증 암호 (GCM)
 * @ingroup authcrypto_gcm
 * @brief 기밀성, 무결성을 지원하는 암호 알고리즘 API
 */

/**
 * @ingroup authcrypto_gcm
 * @anchor edge_gcm_enc
 * @brief 기밀성과 무결성을 지원하는 대칭키 암호 함수. 입력되는 길이 정보는 모두 byte 단위 이다.
 * @param p_cipherID [in] int 암호화에 사용할 대칭키 알고리즘
 * @param p_key [in] uint8_t * 암호 알고리즘에 사용되는 대칭 키 
 * @param p_keyLen [in] uint32_t 대칭 키의 길이 
 * @param p_add [in] uint8_t * 추가 인증데이터 (optional, 최소 0, 최대 2^64-1)
 * @param p_addLen [in] uint64_t 추가 인증데이터의 길이
 * @param p_iv [in] uint8_t * 초기 벡터 데이터 (필수 값으로 0이 될수 없다. 최소 1, 최대 2^64-1)
 * @param p_ivLen [in] uint64_t 초기 벡터 데이터의 길이
 * @param p_input [in] uint8_t * 암호화 대상 평문 (최대 2^39-256)
 * @param p_inputLen [in] uint64_t 암호화 대상 평문의 길이 
 * @param p_output [out] uint8_t * 암호화된 암호문.  (암호화 대상이 없을 경우에도 버퍼 입력 필요 NULL 허용하지 않음)
 * @param p_outputLen [out] uint64_t * 암호문의 길이. (암호화 대상이 없을 경우에도 버퍼 입력 필요 NULL 허용하지 않음)
 * @param p_reqTagLen [in] uint32_t 인증 태그의 길이 값. 인증의 강도를 나타내는 변수로 일반적인 값으로 [12,13,14,15,16]이 사용된다.
 * @param p_tag [out] uint8_t * 요청한 태그 길이 값에 대한 태그
 * @brief <ul><li><pre>
 * 키 길이 제한 -  SEED : 16 byte</li>
 *                 ARIA : 16 / 24 / 32 byte
 *                 LEA  : 16 / 24 / 32 byte </pre></ul>
 * @remark p_outputLen의 경우 타잎을 필히 맞춰줘야 한다. 64비트 길이의 정수 포인터로 이를 지키지 않을시 오류가 발생함.
 * @see edge_gcm_dec
 * @return EDGE_ERR_SUCCESS 성공 \n
 *        그외 실패에 따른 오류 코드
 */
EDGE_EXPORT int         edge_gcm_enc                        (const int p_cipherID, uint8_t * p_key, uint32_t p_keyLen,
                                                             uint8_t * p_add, uint64_t p_addLen,
                                                             uint8_t * p_iv, uint64_t p_ivLen,
                                                             uint8_t * p_input, uint64_t p_inputLen,
                                                             uint8_t * p_output, uint64_t * p_outputLen,
                                                             uint32_t p_reqTagLen, uint8_t * p_tag);
typedef     int         (*fp_edge_gcm_enc)                  (const int, uint8_t *, uint32_t,
                                                             uint8_t *, uint64_t,
                                                             uint8_t *, uint64_t,
                                                             uint8_t *, uint64_t,
                                                             uint8_t *, uint64_t *,
                                                             uint32_t, uint8_t *);

/**
 * @ingroup authcrypto_gcm
 * @anchor edge_gcm_dec
 * @brief 기밀성과 무결성을 지원하는 대칭키 복호화 함수. 입력되는 길이 정보는 모두 byte 단위 이다.
 * @param p_cipherID [in] int 암호화에 사용할 대칭키 알고리즘
 * @param p_key [in] uint8_t * 암호 알고리즘에 사용되는 대칭 키 
 * @param p_keyLen [in] uint32_t 대칭 키의 길이 
 * @param p_add [in] uint8_t * 추가 인증데이터 (optional, 최소 0, 최대 2^64-1)
 * @param p_addLen [in] uint64_t 추가 인증데이터의 길이
 * @param p_iv [in] uint8_t * 초기 벡터 데이터 (필수 값으로 0이 될수 없다. 최소 1, 최대 2^64-1)
 * @param p_ivLen [in] uint64_t 초기 벡터 데이터의 길이
 * @param p_input [in] uint8_t * 암호화된 암호문 
 * @param p_inputLen [in] uint64_t 암호문의 길이
 * @param p_output [out] uint8_t * 암호화 대상 평문
 * @param p_outputLen [out] uint64_t * 평문의 길이
 * @param p_tag [in] uint8_t * 태그 값.
 * @param p_tagLen [in] uint32_t 태그 값의 길이.
 * @brief <ul><li><pre>
 * 키 길이 제한 -  SEED : 16 byte</li>
 *                 ARIA : 16 / 24 / 32 byte
 *                 LEA  : 16 / 24 / 32 byte </pre></ul>
 * @remark p_outputLen의 경우 타잎을 필히 맞춰줘야 한다. 64비트 길이의 정수 포인터로 이를 지키지 않을시 오류가 발생함.
 * @see edge_gcm_enc
 * @return EDGE_ERR_SUCCESS 성공 \n
 *        그외 실패에 따른 오류 코드
 */
EDGE_EXPORT int         edge_gcm_dec                        (const int p_cipherID, uint8_t * p_key, uint32_t p_keyLen,
                                                             uint8_t * p_add, uint64_t p_addLen,
                                                             uint8_t * p_iv, uint64_t p_ivLen,
                                                             uint8_t * p_input, uint64_t p_inputLen,
                                                             uint8_t * p_output, uint64_t * p_outputLen,
                                                             uint8_t * p_tag, uint32_t p_tagLen);
typedef     int         (*fp_edge_gcm_dec)                  (const int, uint8_t *, uint32_t,
                                                             uint8_t *, uint64_t,
                                                             uint8_t *, uint64_t,
                                                             uint8_t *, uint64_t,
                                                             uint8_t *, uint64_t *,
                                                             uint8_t *, uint32_t);

/**
 * @defgroup authcrypto_ccm 메시지 인증 암호(CCM)
 * @ingroup authcrypto_ccm
 * @brief 기밀성, 무결성을 지원하는 암호 알고리즘 API
 */
/**
 * @ingroup authcrypto_ccm
 * @anchor edge_ccm_enc
 * @brief 기밀성과 무결성을 지원하는 대칭키 암호 함수. 입력되는 길이 정보는 모두 byte 단위 이다.
 * @param p_cipherID [in] int 암호화에 사용할 대칭키 알고리즘
 * @param p_key [in] uint8_t * 암호 알고리즘에 사용되는 대칭 키 
 * @param p_keyLen [in] uint32_t 대칭 키의 길이 
 * @param p_add [in] uint8_t * 추가 인증데이터 (optional)
 * @param p_addLen [in] uint64_t 추가 인증데이터의 길이
 * @param p_nonce [in] uint8_t * 랜덤 값. 랜덤 값의 길이는 다음의 제한조건을 만족해야 한다 [7,8,9,10,11,12,13]
 * @param p_nonceLen [in] uint32_t 랜덤 값의 길이
 * @param p_input [in] uint8_t * 암호화 대상 평문
 * @param p_inputLen [in] uint64_t 암호화 대상 평문의 길이 
 * @param p_reqTagLen [in] uint32_t 요청 인증 태그 값의 길이. 길이는 다음 제한조건을 만족해야 한다 [4,6,8,10,12,14,16]
 * @param p_output [out] uint8_t * 암호화된 암호문과 태그 (암호문과 태그가 붙어서 나온다)
 * @param p_outputLen [out] uint64_t * 암호문의 길이. 
 * @brief <ul><li><pre>
 * 키 길이 제한 -  SEED : 16 byte</li>
 *                 ARIA : 16 / 24 / 32 byte
 *                 LEA  : 16 / 24 / 32 byte </pre></ul>
 * @remark p_outputLen의 경우 타잎을 필히 맞춰줘야 한다. 64비트 길이의 정수 포인터로 이를 지키지 않을시 오류가 발생함.
 * @see edge_ccm_dec
 * @return EDGE_ERR_SUCCESS 성공 \n
 *        그외 실패에 따른 오류 코드
 */
EDGE_EXPORT int         edge_ccm_enc                        (int p_cipherID, uint8_t * p_key, uint32_t p_keyLen,
                                                             uint8_t * p_add, uint64_t p_addLen,
                                                             uint8_t * p_nonce, uint32_t p_nonceLen,
                                                             uint8_t * p_input, uint64_t p_inputLen,
                                                             uint32_t p_reqTagLen,
                                                             uint8_t * p_output, uint64_t * p_outputLen);
typedef     int         (*fp_edge_ccm_enc)                  (int, uint8_t *, uint32_t,
                                                             uint8_t *, uint64_t,
                                                             uint8_t *, uint32_t,
                                                             uint8_t *, uint64_t,
                                                             uint32_t,
                                                             uint8_t *, uint64_t *);

/**
 * @ingroup authcrypto_ccm
 * @anchor edge_ccm_dec
 * @brief 기밀성과 무결성을 지원하는 대칭키 복호화 함수. 입력되는 길이 정보는 모두 byte 단위 이다.
 * @param p_cipherID [in] int 암호화에 사용할 대칭키 알고리즘
 * @param p_key [in] uint8_t * 암호 알고리즘에 사용되는 대칭 키 
 * @param p_keyLen [in] uint32_t 대칭 키의 길이 
 * @param p_add [in] uint8_t * 추가 인증데이터 (optional)
 * @param p_addLen [in] uint64_t 추가 인증데이터의 길이
 * @param p_nonce [in] uint8_t * 랜덤 값. 랜덤 값의 길이는 다음의 제한조건을 만족해야 한다 [7,8,9,10,11,12,13]
 * @param p_nonceLen [in] uint32_t 랜덤 값의 길이
 * @param p_input [in] uint8_t * 암호화된 암호문 
 * @param p_inputLen [in] uint64_t 암호문의 길이
 * @param p_tagLen [in] uint32_t 암호화시 사용된 태그 길이. 길이는 다음 제한조건을 만족해야 한다 [4,6,8,10,12,14,16]
 * @param p_output [out] uint8_t * 암호화 대상 평문
 * @param p_outputLen [out] uint64_t * 평문의 길이
 * @brief <ul><li><pre>
 * 키 길이 제한 -  SEED : 16 byte</li>
 *                 ARIA : 16 / 24 / 32 byte
 *                 LEA  : 16 / 24 / 32 byte </pre></ul>
 * @remark p_outputLen의 경우 타잎을 필히 맞춰줘야 한다. 64비트 길이의 정수 포인터로 이를 지키지 않을시 오류가 발생함.
 * @see edge_ccm_enc
 * @return EDGE_ERR_SUCCESS 성공 \n
 *        그외 실패에 따른 오류 코드
 */
EDGE_EXPORT int         edge_ccm_dec                        (int p_cipherID, uint8_t * p_key, uint32_t p_keyLen,
                                                             uint8_t * p_add, uint64_t p_addLen,
                                                             uint8_t * p_nonce, uint32_t p_nonceLen,
                                                             uint8_t * p_input, uint64_t p_inputLen,
                                                             uint32_t p_tagLen,
                                                             uint8_t * p_output, uint64_t * p_outputLen);
typedef     int         (*fp_edge_ccm_dec)                  (int, uint8_t *, uint32_t,
                                                             uint8_t *, uint64_t,
                                                             uint8_t *, uint32_t,
                                                             uint8_t *, uint64_t,
                                                             uint32_t,
                                                             uint8_t *, uint64_t *);

/**
 * @defgroup hash 해쉬 함수(Hash)
 * @ingroup hash
 * @brief 해쉬 함수 
*/
#define EDGE_HASH_MAX_BLOCK_SIZE                            128 // SHA512
#define EDGE_HASH_MAX_DIGEST_SIZE                           64  // SHA512

/**
 * @ingroup hash
 * Hash Algorighm ID
 */
#define EDGE_HASH                                           200
#define EDGE_HASH_ID_HAS160                                 (EDGE_HASH + 1)
#define EDGE_HASH_ID_SHA1                                   (EDGE_HASH + 2)
#define EDGE_HASH_ID_SHA224                                 (EDGE_HASH + 3)
#define EDGE_HASH_ID_SHA256                                 (EDGE_HASH + 4)
#define EDGE_HASH_ID_SHA384                                 (EDGE_HASH + 5)
#define EDGE_HASH_ID_SHA512                                 (EDGE_HASH + 6)
#define EDGE_HASH_ID_UNKNOWN                                (EDGE_HASH + 7)

/**
 * @ingroup hash
 * @anchor edge_hash
 * @brief 메시지 축약 함수 
 * @param p_hashID [in] const int 해쉬 알고리즘 아이디
 * @param p_input [in] const uint8_t * 해쉬 대상 데이터
 * @param p_inputLength [in] const uint32_t 대상 데이터의 길이
 * @param p_hash [out] uint8_t * 해쉬 결과 값
 * @param p_hashLength [out] uint32_t * 해쉬 결과 값의 길이
 * @return EDGE_ERR_SUCCESS 성공 \n
 *        그외 실패에 따른 오류 코드
 */
EDGE_EXPORT int     edge_hash                               (const int p_hashID,
                                                             const uint8_t *p_input,
                                                             const uint32_t p_inputLength,
                                                             uint8_t *p_hash,
                                                             uint32_t *p_hashLength);
typedef     int     (*fp_edge_hash)                         (const int,
                                                             const uint8_t *,
                                                             const uint32_t,
                                                             uint8_t *,
                                                             uint32_t *);


typedef struct _edge_hash_ctx_ EDGE_HASH_CTX;

/**
 * @ingroup hash
 * @anchor edge_hash_ctx_new
 * @brief 해쉬 함수에 사용되는 context 생성 (init/update/final에 사용)
 *        사용 후 edge_hash_ctx_free로 메모리 해제해 주어야 한다. 
 * @see edge_hash_ctx_free
 * @return EDGE_HASH_CTX * 내부적인 상태 정보를 저장하고 있는 구조체의 주소. \n
 *         NULL 메모리 할당 실패. 
 */
EDGE_EXPORT EDGE_HASH_CTX * edge_hash_ctx_new               (void);
typedef     EDGE_HASH_CTX * (*fp_edge_hash_ctx_new)         (void);

/**
 * @ingroup hash
 * @anchor edge_hash_ctx_reset
 * @brief 해쉬 함수에 사용한 context 메모리 초기화 함수.
 * @Param p_context [in] EDGE_HASH_CTX * 해쉬 context
 * @see edge_hash_ctx_new
 * @see edge_hash_ctx_free
 * @return void
 */
EDGE_EXPORT void        edge_hash_ctx_reset                 (EDGE_HASH_CTX * p_context);
typedef     void        (*fp_edge_hash_ctx_reset)           (EDGE_HASH_CTX *);

/**
 * @ingroup hash
 * @anchor edge_hash_ctx_free
 * @brief 해쉬 함수에 사용한 context 메모리 해제 함수.
 * @Param p_context [in] EDGE_HASH_CTX * 해쉬 context
 * @see edge_hash_ctx_new
 * @return void
 */
EDGE_EXPORT void        edge_hash_ctx_free                  (EDGE_HASH_CTX * p_context);
typedef     void        (*fp_edge_hash_ctx_free)            (EDGE_HASH_CTX *);


/**
 * @ingroup hash
 * @anchor edge_hash_init
 * @brief 해쉬 초기화 함수
 * @param p_context [in] EDGE_HASH_CTX * 내부적인 상태 관리를 위한 context edge_hash_ctx_new로 생성한다. 
 * @param p_hashID [in] const int 해쉬 알고리즘 아이디
 * @see edge_hash_update
 * @see edge_hash_final
 * @return EDGE_ERR_SUCCESS 성공 \n
 *        그외 실패에 따른 오류 코드
 */
EDGE_EXPORT int         edge_hash_init                      (EDGE_HASH_CTX *p_context, const int p_hashID);
typedef     int         (*fp_edge_hash_init)                (EDGE_HASH_CTX *, const int);

/**
 * @ingroup hash
 * @anchor edge_hash_update
 * @brief 해쉬 데이터 입력 함수
 * @param p_context [in] EDGE_HASH_CTX * 내부적인 상태 관리를 위한 context edge_hash_ctx_new로 생성한다. 
 * @param p_input [in] const uint8_t * 해쉬 대상 데이터
 * @param p_inputLength [in] const uint32_t 대상 데이터의 길이
 * @see edge_hash_init
 * @see edge_hash_final
 * @return EDGE_ERR_SUCCESS 성공 \n
 *        그외 실패에 따른 오류 코드
 */
EDGE_EXPORT int         edge_hash_update                    (EDGE_HASH_CTX *p_context,
                                                             const uint8_t *p_input,
                                                             const uint32_t p_inputLength);
typedef     int         (*fp_edge_hash_update)              (EDGE_HASH_CTX *,
                                                             const uint8_t *,
                                                             const uint32_t);

/**
 * @ingroup hash
 * @anchor edge_hash_final
 * @Brief 해쉬 마지막 함수
 * @param p_context [in] EDGE_HASH_CTX * 내부적인 상태 관리를 위한 context edge_hash_ctx_new로 생성한다. 
 * @param p_hash [out] uint8_t * 해쉬 결과 값
 * @param p_hashLength [out] uint32_t * 해쉬 결과 값의 길이
 * @see edge_hash_init
 * @see edge_hash_update
 * @return EDGE_ERR_SUCCESS 성공 \n
 *        그외 실패에 따른 오류 코드
 */
EDGE_EXPORT int         edge_hash_final                     (EDGE_HASH_CTX *p_context,
                                                             uint8_t *p_hash,
                                                             uint32_t *p_hashLength);
typedef     int         (*fp_edge_hash_final)               (EDGE_HASH_CTX *,
                                                             uint8_t *,
                                                             uint32_t *);


/**
 * @defgroup mac 메시지 인증(MAC)
 * @ingroup mac
 * @brief 메시지인증 함수로 내부적으로 해쉬 기반 HMAC과 블럭암호 기반 CMAC이 있다.
 */

#define EDGE_MAC                                            1000
#define EDGE_CMAC                                           (EDGE_MAC + EDGE_CIPHER)
#define EDGE_CMAC_ID_AES128                                 (EDGE_MAC + EDGE_CIPHER_ID_AES128)
#define EDGE_CMAC_ID_AES192                                 (EDGE_MAC + EDGE_CIPHER_ID_AES192)
#define EDGE_CMAC_ID_AES256                                 (EDGE_MAC + EDGE_CIPHER_ID_AES256)
#define EDGE_CMAC_ID_SEED128                                (EDGE_MAC + EDGE_CIPHER_ID_SEED128)
#define EDGE_CMAC_ID_SEED256                                (EDGE_MAC + EDGE_CIPHER_ID_SEED256)
#define EDGE_CMAC_ID_ARIA128                                (EDGE_MAC + EDGE_CIPHER_ID_ARIA128)
#define EDGE_CMAC_ID_ARIA192                                (EDGE_MAC + EDGE_CIPHER_ID_ARIA192)
#define EDGE_CMAC_ID_ARIA256                                (EDGE_MAC + EDGE_CIPHER_ID_ARIA256)
#define EDGE_CMAC_ID_HIGHT                                  (EDGE_MAC + EDGE_CIPHER_ID_HIGHT)
#define EDGE_CMAC_ID_LEA128                                 (EDGE_MAC + EDGE_CIPHER_ID_LEA128)
#define EDGE_CMAC_ID_LEA192                                 (EDGE_MAC + EDGE_CIPHER_ID_LEA192)
#define EDGE_CMAC_ID_LEA256                                 (EDGE_MAC + EDGE_CIPHER_ID_LEA256)
#define EDGE_CMAC_ID_UNKNOWN                                (EDGE_MAC + EDGE_CIPHER_ID_UNKNOWN)

#define EDGE_HMAC                                           (EDGE_MAC + EDGE_HASH)
#define EDGE_HMAC_ID_HAS160                                 (EDGE_MAC + EDGE_HASH_ID_HAS160)
#define EDGE_HMAC_ID_SHA1                                   (EDGE_MAC + EDGE_HASH_ID_SHA1)
#define EDGE_HMAC_ID_SHA224                                 (EDGE_MAC + EDGE_HASH_ID_SHA224)
#define EDGE_HMAC_ID_SHA256                                 (EDGE_MAC + EDGE_HASH_ID_SHA256)
#define EDGE_HMAC_ID_SHA384                                 (EDGE_MAC + EDGE_HASH_ID_SHA384)
#define EDGE_HMAC_ID_SHA512                                 (EDGE_MAC + EDGE_HASH_ID_SHA512)
#define EDGE_HMAC_ID_UNKNOWN                                (EDGE_MAC + EDGE_HASH_ID_UNKNOWN)

/**
 * @ingroup mac
 * @anchor edge_mac
 * @brief 메시지 인증 함수. \n
 *        HMAC에서 사용하는 비밀키는 해쉬 함수 출력 크기 보다 같거나 커야 한다. \n
          SHA224 : 28, SHA256 : 32, SHA384 : 48, SHA512 : 64
 * @param p_key [in] uint8_t * mac에 사용되는 키
 * @param p_keyLen [in] uint32_t 키의 길이
 * @param p_macID [in] int MAC 알고리즘 아이디
 * @param p_input [in] uint8_t * 대상 데이터
 * @param p_inputLen [in] uint32_t 데이터의 길이
 * @param p_mac [out] uint8_t * MAC 결과 값
 * @param p_macLen [out] uint32_t * MAC 결과 값의 길이
 * @brief <ul><li>키 길이 제한</li>
 * <ol><li>HMAC</li>
 * <ul><li>SHA224 : 최소 28 byte, 최대 64 byte</li>
 *     <li>SHA256 : 최소 32 byte, 최대 64 byte</li>
 *     <li>SHA384 : 최소 48 byte, 최대 128 byte</li>
 *     <li>SHA512 : 최소 64 byte, 최대 128 byte</li></ul>
 * <li>CMAC</li>
 * <ul><li>SEED  : 16 byte</li>
 *     <li>HIGHT : 16 byte</li>
 *     <li>ARIA  : 16 / 24 / 32 byte</li>
 *     <li>LEA   : 16 / 24 / 32 byte</li></ul></ol></ul><br>
 * @brief <ul><li>메시지 인증코드 길이</li>
 * <ol><li>HMAC</li>
 * <ul><li>SHA224 : 28 byte</li>
 *     <li>SHA256 : 32 byte</li>
 *     <li>SHA384 : 48 byte</li>
 *     <li>SHA512 : 64 byte</li></ul>
 * <li>CMAC</li>
 * <ul><li>SEED  : 16 byte</li>
 *     <li>HIGHT : 8 byte</li>
 *     <li>ARIA  : 16 byte</li>
 *     <li>LEA   : 16 byte</li></ul></ol></ul>
 * @return EDGE_ERR_SUCCESS 성공 \n
 *        그외 실패에 따른 오류 코드
 */
EDGE_EXPORT int         edge_mac                            (int p_macID,
                                                             uint8_t * p_key, uint32_t p_keyLen,
                                                             uint8_t *p_input, uint32_t p_inputLen,
                                                             uint8_t *p_mac, uint32_t * p_macLen);
typedef     int         (*fp_edge_mac)                      (int, uint8_t *, uint32_t,
                                                             uint8_t *, uint32_t,
                                                             uint8_t  *, uint32_t *);

typedef struct _edge_mac_ctx_ EDGE_MAC_CTX;

/**
 * @ingroup mac
 * @anchor edge_mac_ctx_new
 * @brief MAC에 사용되는 context 생성 (init/update/final에 사용)
 *        사용 후 edge_mac_ctx_free로 메모리 해제해 주어야 한다. 
 * @see edge_mac_ctx_free
 * @return EDGE_MAC_CTX * 내부적인 상태 정보를 저장하고 있는 구조체의 주소. \n
 *         NULL 메모리 할당 실패. 
 */
EDGE_EXPORT EDGE_MAC_CTX * edge_mac_ctx_new                 (void);
typedef     EDGE_MAC_CTX * (*fp_edge_mac_ctx_new)           (void);

/**
 * @ingroup mac
 * @anchor edge_mac_ctx_reset
 * @brief MAC에 사용한 context 메모리 초기화 함수.
 * @param p_context [in] EDGE_MAC_CTX * MAC context
 * @see edge_mac_ctx_new
 * @see edge_mac_ctx_free
 * @return void
 */
EDGE_EXPORT void        edge_mac_ctx_reset                  (EDGE_MAC_CTX *p_context);
typedef     void        (*fp_edge_mac_ctx_reset)            (EDGE_MAC_CTX *);

/**
 * @ingroup mac
 * @anchor edge_mac_ctx_free
 * @brief MAC에 사용한 context 메모리 해제 함수.
 * @param p_context [in] EDGE_MAC_CTX * MAC context
 * @see edge_mac_ctx_new
 * @return void
 */
EDGE_EXPORT void        edge_mac_ctx_free                   (EDGE_MAC_CTX *p_context);
typedef     void        (*fp_edge_mac_ctx_free)             (EDGE_MAC_CTX *);

/**
 * @ingroup mac
 * @anchor edge_mac_init
 * @brief 메시지 인증 초기화 함수
 * @param p_context [in] EDGE_MAC_CTX * 내부적인 상태 관리를 위한 context edge_hash_ctx_new로 생성한다. 
 * @param p_macID [in] const int MAC 알고리즘 아이디
 * @param p_key [in] uint8_t * mac에 사용되는 키
 * @param p_keyLen [in] uint32_t 키의 길이
 * @brief <ul><li>키 길이 제한</li>
 * <ol><li>HMAC</li>
 * <ul><li>SHA224 : 최소 28 byte, 최대 64 byte</li>
 *     <li>SHA256 : 최소 32 byte, 최대 64 byte</li>
 *     <li>SHA384 : 최소 48 byte, 최대 128 byte</li>
 *     <li>SHA512 : 최소 64 byte, 최대 128 byte</li></ul>
 * <li>CMAC</li>
 * <ul><li>SEED  : 16 byte</li>
 *     <li>HIGHT : 16 byte</li>
 *     <li>ARIA  : 16 / 24 / 32 byte</li>
 *     <li>LEA   : 16 / 24 / 32 byte</li></ul></ol></ul><br>
 * @brief <ul><li>메시지 인증코드 길이</li>
 * <ol><li>HMAC</li>
 * <ul><li>SHA224 : 28 byte</li>
 *     <li>SHA256 : 32 byte</li>
 *     <li>SHA384 : 48 byte</li>
 *     <li>SHA512 : 64 byte</li></ul>
 * <li>CMAC</li>
 * <ul><li>SEED  : 16 byte</li>
 *     <li>HIGHT : 8 byte</li>
 *     <li>ARIA  : 16 byte</li>
 *     <li>LEA   : 16 byte</li></ul></ol></ul>
 * @return EDGE_ERR_SUCCESS 성공 \n
 *        그외 실패에 따른 오류 코드
 */
EDGE_EXPORT int         edge_mac_init                       (EDGE_MAC_CTX *p_context, const int p_macID,
                                                             uint8_t *p_key, uint32_t p_keyLen);
typedef     int         (*fp_edge_mac_init)                 (EDGE_MAC_CTX *, const int,
                                                             uint8_t *, uint32_t);

/**
 * @ingroup mac
 * @anchor edge_mac_update
 * @brief 메시지 인증 데이터 입력 함수
 * @param p_context [in] EDGE_MAC_CTX * 내부적인 상태 관리를 위한 context edge_hash_ctx_new로 생성한다. 
 * @param p_input [in] uint8_t * 대상 데이터
 * @param p_inputLen [in] uint32_t 데이터의 길이
 * @return EDGE_ERR_SUCCESS 성공 \n
 *        그외 실패에 따른 오류 코드
 */
EDGE_EXPORT int         edge_mac_update                     (EDGE_MAC_CTX *p_context,
                                                             uint8_t *p_input, uint32_t p_inputLen);
typedef     int         (*fp_edge_mac_update)               (EDGE_MAC_CTX *,
                                                             uint8_t *, uint32_t);

/**
 * @ingroup mac
 * @anchor edge_mac_final
 * @brief 메시지 인증 종료 함수
 * @param p_context [in] EDGE_MAC_CTX * 내부적인 상태 관리를 위한 context edge_hash_ctx_new로 생성한다. 
 * @param p_mac [out] uint8_t * MAC 결과 값
 * @param p_macLen [out] uint32_t * MAC 결과 값의 길이
 * @return EDGE_ERR_SUCCESS 성공 \n
 *        그외 실패에 따른 오류 코드
 */
EDGE_EXPORT int         edge_mac_final                      (EDGE_MAC_CTX *p_conctext,
                                                             uint8_t *p_mac, uint32_t *p_macLen);
typedef     int         (*fp_edge_mac_final)                (EDGE_MAC_CTX *,
                                                             uint8_t *, uint32_t *);


#define EDGE_ASYM                                           50000
#define EDGE_ASYM_ID_KCDSA                                  (EDGE_ASYM + 1000)
#define EDGE_ASYM_ID_DH                                     (EDGE_ASYM + 1200)  // for keyagreement DH
#define EDGE_ASYM_ID_DOMAIN_PARAM                           (EDGE_ASYM + 1300)  // verify key pair (check domain param)
#define EDGE_ASYM_ID_RSA                                    (EDGE_ASYM + 2000)

#define EDGE_ASYM_ID_ECDSA                                  (EDGE_ASYM + 3000)
#define EDGE_ASYM_ID_EC_KCDSA                               (EDGE_ASYM + 3100)
#define EDGE_ASYM_ID_ECDH                                   (EDGE_ASYM + 3200)  // for keyagreement ECDH

#define EDGE_ASYM_ID_ECC_SECP192K1                          1
#define EDGE_ASYM_ID_ECC_SECP192R1                          2
#define EDGE_ASYM_ID_ECC_SECP224K1                          3
#define EDGE_ASYM_ID_ECC_SECP224R1                          4
#define EDGE_ASYM_ID_ECC_SECP256K1                          5
#define EDGE_ASYM_ID_ECC_SECP256R1                          6
#define EDGE_ASYM_ID_ECC_SECP384R1                          7
#define EDGE_ASYM_ID_ECC_SECP521R1                          8
#define EDGE_ASYM_ID_ECC_SECT163K1                          9
#define EDGE_ASYM_ID_ECC_SECT163R1                          10
#define EDGE_ASYM_ID_ECC_SECT163R2                          11
#define EDGE_ASYM_ID_ECC_SECT233K1                          12
#define EDGE_ASYM_ID_ECC_SECT233R1                          13
#define EDGE_ASYM_ID_ECC_SECT239K1                          14
#define EDGE_ASYM_ID_ECC_SECT283K1                          15
#define EDGE_ASYM_ID_ECC_SECT283R1                          16
#define EDGE_ASYM_ID_ECC_SECT409K1                          17
#define EDGE_ASYM_ID_ECC_SECT409R1                          18
#define EDGE_ASYM_ID_ECC_SECT571K1                          19
#define EDGE_ASYM_ID_ECC_SECT571R1                          20

#define EDGE_ASYM_ID_ECC_P192                               2
#define EDGE_ASYM_ID_ECC_P224                               4
#define EDGE_ASYM_ID_ECC_P256                               6
#define EDGE_ASYM_ID_ECC_P384                               7
#define EDGE_ASYM_ID_ECC_P521                               8
#define EDGE_ASYM_ID_ECC_B163                               11
#define EDGE_ASYM_ID_ECC_B233                               13
#define EDGE_ASYM_ID_ECC_B283                               16
#define EDGE_ASYM_ID_ECC_B409                               18
#define EDGE_ASYM_ID_ECC_B571                               20
#define EDGE_ASYM_ID_ECC_K163                               9
#define EDGE_ASYM_ID_ECC_K233                               12
#define EDGE_ASYM_ID_ECC_K283                               15
#define EDGE_ASYM_ID_ECC_K409                               17
#define EDGE_ASYM_ID_ECC_K571                               19

/*
 * KCDSA security strength 
 * security strength        80           112             128
 * prime P bit length      1024          2048            3072
 * prime Q bit length      160         224, 256          256
 * hash                  HAS-160    SHA-224, SHA-256    SHA-256
 */
#define EDGE_DOMAIN_PARAM_P_MAX                             384
#define EDGE_DOMAIN_PARAM_Q_MAX                             32



/**
 * @defgroup digisign 전자 서명(Digital Signatures)
 * @ingroup digisign
 * @brief 비대칭키 알고리즘 전자 서명으로 지원하는 알고리즘은 다음과 같다. 
 *  - RSA (PSS, PKCS1_v15)
 *  - ECDSA
 *  - EC_KCDSA
 *  - KCDSA
 *  ECDSA와 EC_KCDSA의 알고리즘 입력은 ECC 알고리즘과 결합한 형태로 넣어 주어야 한다. \n
 *  ex> ECDSA_B233을 사용하고자 하는 경우 Algorighm ID : EDGE_ASYM_ECDSA + EDGE_ASYM_ID_ECC_B233 \n
 *  EDGE_ASYM_DSA와 EDGE_ASYM_DOMAIN_PARAM은 여기에 사용되지 않는다. 
 */

/**
 * @ingroup digisign
 * @anchor EDGE_RSA_SIGN_MODE
 * @brief RSA 서명 인코딩 모드
 */
typedef enum
{
    EDGE_RSA_SIGN_MODE_PSS = 0,       /**< PSS 인코딩 모드 */
    EDGE_RSA_SIGN_MODE_PKCS1_v15      /**< PKCS1_v15 인코딩 모드 */
} EDGE_RSA_SIGN_MODE;

/**
 * @ingroup digisign
 * @anchor EDGE_DOMAIN_PARAM
 * @struct EDGE_DOMAIN_PARAM
 * @brief DH, KCDSA에서 사용하는 전자서명 도메인 파라미터
 * @brief P, Q 길이 제한 -  SHA224 - P : 2048 bit, Q : 224 bit
 *                          SHA256 - P : 2048 bit, Q : 256 bit
 */
typedef struct { // domain param
    uint8_t             m_p[EDGE_DOMAIN_PARAM_P_MAX];   /**< Domain param P */
    uint32_t            m_pLen;                         /**< P 길이 */
    uint8_t             m_q[EDGE_DOMAIN_PARAM_Q_MAX];   /**< Domain param Q */
    uint32_t            m_qLen;                         /**< Q 길이 */
    uint8_t             m_g[EDGE_DOMAIN_PARAM_P_MAX];   /**< Domain param G */
    uint32_t            m_gLen;                         /**< G 길이 */
} EDGE_DOMAIN_PARAM;

/* default salt length = hash output length */
#define EDGE_RSA_DEFAULT_SALT_LENGTH        -1

/**
 * @ingroup digisign
 * @anchor EDGE_ASYM_SIGN_PARAM
 * @struct EDGE_ASYM_SIGN_PARAM
 * @see EDGE_DOMAIN_PARAM
 * @brief 비대칭키 전자서명에 사용되는 세부 정보
 */
typedef struct {
    int             m_asymAlg;                  /**< 비대칭키 알고리즘 */
    int             m_hashAlg;                  /**< 서명에 사용될 해쉬 알고리즘 */
    /**
     * @struct rsa
     * @brief RSA 서명에 사용될 세부 구조체 
     */
    struct {
        EDGE_RSA_SIGN_MODE  m_signMode;     /**< RSA 서명 인코딩 @see EDGE_RSA_SIGN_MODE */
        int                 m_mgfHashAlg;   /**< EDGE_RSA_SIGN_MODE_PSS 에 사용되는 MGF 해쉬 알고리즘 */
        int                 m_saltLength;   /**< EDGE_RSA_SIGN_MODE_PSS에 사용되는 salt의 길이 일반적으로 EDGE_RSA_DEFAULT_SALT_LENGTH를 설정 */
    } rsa;              
    /**
     * @struct kcdsa
     * @brief KCDSA 서명에 사용될 세부 구조체 
     */
    struct {
        EDGE_DOMAIN_PARAM       m_domainParam;  /**< 도메인 파라미터 @see EDGE_DOMAIN_PARAM */
    } kcdsa;
} EDGE_ASYM_SIGN_PARAM;


/**
 * @ingroup digisign
 * @anchor edge_asym_sign
 * @brief 비대칭키 전자 서명 함수.
 * @param p_key [in] uint8_t * 전자 서명에 사용되는 비대칭 키  (RSA의 키는 ASN.1인코딩된 키를 사용한다.)
 * @param p_keyLen [in] uint32_t 비대칭키 길이 
 * @param p_data [in] uint8_t * 전자 서명  대상 평문 
 * @param p_dataLen [in] uint32_t 평문 길이 
 * @param p_signData [out] uint8_t * 전자 서명 데이터.
 * @param p_signDataLen [out] uint32_t * 전자 서명 데이터의 길이
 * @param p_signParam [in] EDGE_ASYM_SIGN_PARAM * 알고리즘에 적용할 세부 설정x
 * <table>
 * <caption id="multi_row">키 길이에 따른 Hash, Salt 길이 제한</caption>
 * <tr><th>키 길이
 * <th>메시지 Hash
 * <th>MGF Hash
 * <th>Salt 길이
 * <tr><td rowspan="2">256 byte
 * <td>SHA-224
 * <td>SHA-224
 * <td>28 byte
 * <tr><td>SHA-256
 * <td>SHA-256
 * <td>32 byte
 * <tr><td>384 byte
 * <td>SHA-256
 * <td>SHA-256
 * <td>32 byte
 * </table>
 * @see edge_asym_verify
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */ 
EDGE_EXPORT int         edge_asym_sign              (uint8_t * p_key, uint32_t p_keyLen,
                                                     EDGE_ASYM_SIGN_PARAM * p_signParam,
                                                     uint8_t * p_data, uint32_t p_dataLen,
                                                     uint8_t * p_signData, uint32_t * p_signDataLen);
typedef     int         (*fp_edge_asym_sign)        (uint8_t *, uint32_t,
                                                     EDGE_ASYM_SIGN_PARAM *,
                                                     uint8_t *, uint32_t,
                                                     uint8_t *, uint32_t *);

/**
 * @ingroup digisign
 * @anchor edge_asym_verify
 * @brief 비대칭키 전자 서명 검증 함수.
 * @param p_key [in] uint8_t * 전자 서명에 사용되는 비대칭 키  (RSA의 키는 ASN.1인코딩된 키를 사용한다.)
 * @param p_keyLen [in] uint32_t 비대칭키 길이 
 * @param p_data [in] uint8_t * 전자 서명  대상 평문 
 * @param p_dataLen [in] uint32_t 평문 길이 
 * @param p_signData [in] uint8_t * 전자 서명 데이터
 * @param p_signDataLen [in] uint32_t 전자 서명 데이터의 길이
 * @param p_signParam [in] EDGE_ASYM_SIGN_PARAM * 알고리즘에 적용할 세부 설정
 * <table>
 * <caption id="multi_row">키 길이에 따른 Hash, Salt 길이 제한</caption>
 * <tr><th>키 길이
 * <th>메시지 Hash
 * <th>MGF Hash
 * <th>Salt 길이
 * <tr><td rowspan="2">256 byte
 * <td>SHA-224
 * <td>SHA-224
 * <td>28 byte
 * <tr><td>SHA-256
 * <td>SHA-256
 * <td>32 byte
 * <tr><td>384 byte
 * <td>SHA-256
 * <td>SHA-256
 * <td>32 byte
 * </table>
 * @see edge_asym_sign
 * @return EDGE_ERR_SUCCESS 서명 검증 성공 \n
 *      그외 실패에 따른 오류 코드 
 */ 
EDGE_EXPORT int         edge_asym_verify            (uint8_t * p_key, uint32_t p_keyLen,
                                                     EDGE_ASYM_SIGN_PARAM * p_signParam,
                                                     uint8_t * p_data, uint32_t p_dataLen,
                                                     uint8_t * p_signData, uint32_t p_signDataLen);
typedef     int         (*fp_edge_asym_verify)      (uint8_t *, uint32_t,
                                                     EDGE_ASYM_SIGN_PARAM *,
                                                     uint8_t *, uint32_t,
                                                     uint8_t *, uint32_t);

typedef struct _edge_asym_sign_ctx_ EDGE_ASYM_SIGN_CTX;

/**
 * @ingroup digisign
 * @anchor edge_asym_sign_ctx_new
 * @brief 비대칭키 전자 서명에 사용되는 context 생성 (init/update/final에 사용)
 *        사용 후 edge_asym_sign_ctx_free로 메모리 해제해 주어야 한다. 
 * @see edge_asym_sign_ctx_free
 * @return void * 내부적인 상태 정보를 저장하고 있는 구조체의 주소. \n
 *         NULL 메모리 할당 실패 또는 지원하지 않는 알고리즘.
 */
EDGE_EXPORT EDGE_ASYM_SIGN_CTX * edge_asym_sign_ctx_new (void);
typedef     EDGE_ASYM_SIGN_CTX * (*fp_edge_asym_sign_ctx_new)(void);

/**
 * @ingroup digisign
 * @anchor edge_asym_sign_ctx_reset
 * @brief 비대칭키 전자 서명에 사용되는 context에 할당된 메모리 초기화 함수.
 * @param p_context [in] EDGE_ASYM_SIGN_CTX * 비대칭키 전자 서명에 사용되는 context
 * @see edge_asym_sign_ctx_new
 * @see edge_asym_sign_ctx_free
 * @return void
 */
EDGE_EXPORT void        edge_asym_sign_ctx_reset            (EDGE_ASYM_SIGN_CTX * p_context);
typedef     void        (*fp_edge_asym_sign_ctx_reset)      (EDGE_ASYM_SIGN_CTX *);

/**
 * @ingroup digisign
 * @anchor edge_asym_sign_ctx_free
 * @brief 비대칭키 전자 서명에 사용되는 context 메모리 해제 함수.
 * @param p_context [in] EDGE_ASYM_SIGN_CTX * 비대칭키 전자 서명에 사용되는 context
 * @see edge_asym_sign_ctx_new
 * @return void
 */
EDGE_EXPORT void        edge_asym_sign_ctx_free             (EDGE_ASYM_SIGN_CTX * p_context);
typedef     void        (*fp_edge_asym_sign_ctx_free)       (EDGE_ASYM_SIGN_CTX *);


/**
 * @ingroup digisign
 * @anchor edge_asym_sign_init
 * @brief 비대칭키 전자 서명 초기화 함수.
 * @param p_context [in] EDGE_ASYM_SIGN_CTX * 비대칭키 전자 서명에 사용되는 context
 * @param p_key [in] uint8_t * 전자 서명에 사용되는 비대칭 키  (RSA의 키는 ASN.1인코딩된 키를 사용한다.)
 * @param p_keyLen [in] uint32_t 비대칭키 길이 
 * @param p_signParam [in] EDGE_ASYM_SIGN_PARAM * 알고리즘에 적용할 세부 설정
 * <table>
 * <caption id="multi_row">키 길이에 따른 Hash, Salt 길이 제한</caption>
 * <tr><th>키 길이
 * <th>메시지 Hash
 * <th>MGF Hash
 * <th>Salt 길이
 * <tr><td rowspan="2">256 byte
 * <td>SHA-224
 * <td>SHA-224
 * <td>28 byte
 * <tr><td>SHA-256
 * <td>SHA-256
 * <td>32 byte
 * <tr><td>384 byte
 * <td>SHA-256
 * <td>SHA-256
 * <td>32 byte
 * </table>
 * @see edge_asym_sign_update
 * @see edge_asym_sign_final
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */ 
EDGE_EXPORT int         edge_asym_sign_init         (EDGE_ASYM_SIGN_CTX * p_context,
                                                     uint8_t * p_key, uint32_t p_keyLen,
                                                     EDGE_ASYM_SIGN_PARAM * p_signParam);
typedef     int         (*fp_edge_asym_sign_init)   (EDGE_ASYM_SIGN_CTX *,
                                                     uint8_t *, uint32_t,
                                                     EDGE_ASYM_SIGN_PARAM *);

/**
 * @ingroup digisign
 * @anchor edge_asym_sign_update
 * @brief 비대칭키 전자 서명 데이터 입력 함수.
 * @param p_context [in] EDGE_ASYM_SIGN_CTX * 비대칭키 전자 서명에 사용되는 context
 * @param p_data [in] uint8_t * 전자 서명  대상 평문 
 * @param p_dataLen [in] uint32_t 평문 길이 
 * @see edge_asym_sign_update
 * @see edge_asym_sign_final
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */ 
EDGE_EXPORT int         edge_asym_sign_update       (EDGE_ASYM_SIGN_CTX * p_context,
                                                     uint8_t * p_data, uint32_t p_dataLen);
typedef     int         (*fp_edge_asym_sign_update) (EDGE_ASYM_SIGN_CTX *,
                                                     uint8_t *, uint32_t);

/**
 * @ingroup digisign
 * @anchor edge_asym_sign_final
 * @brief 비대칭키 전자 서명 출력 함수.
 * @param p_context [in] EDGE_ASYM_SIGN_CTX * 비대칭키 전자 서명에 사용되는 context
 * @param p_signData [out] uint8_t * 전자 서명 데이터.
 * @param p_signDataLen [out] uint32_t * 전자 서명 데이터의 길이
 * @see edge_asym_sign_init
 * @see edge_asym_sign_update
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */ 
EDGE_EXPORT int         edge_asym_sign_final        (EDGE_ASYM_SIGN_CTX * p_context,
                                                     uint8_t * p_signData, uint32_t * p_signDataLen);
typedef     int         (*fp_edge_asym_sign_final)  (EDGE_ASYM_SIGN_CTX *,
                                                     uint8_t *, uint32_t *);

/**
 * @ingroup digisign
 * @anchor edge_asym_verify_init
 * @brief 비대칭키 전자 서명 검증 초기화 함수.
 * @param p_context [in] EDGE_ASYM_SIGN_CTX * 비대칭키 전자 서명에 사용되는 context
 * @param p_key [in] uint8_t * 전자 서명에 사용되는 비대칭 키  (RSA의 키는 ASN.1인코딩된 키를 사용한다.)
 * @param p_keyLen [in] uint32_t 비대칭키 길이 
 * @param p_signParam [in] EDGE_ASYM_SIGN_PARAM * 알고리즘에 적용할 세부 설정
 * <table>
 * <caption id="multi_row">키 길이에 따른 Hash, Salt 길이 제한</caption>
 * <tr><th>키 길이
 * <th>메시지 Hash
 * <th>MGF Hash
 * <th>Salt 길이
 * <tr><td rowspan="2">256 byte
 * <td>SHA-224
 * <td>SHA-224
 * <td>28 byte
 * <tr><td>SHA-256
 * <td>SHA-256
 * <td>32 byte
 * <tr><td>384 byte
 * <td>SHA-256
 * <td>SHA-256
 * <td>32 byte
 * </table>
 * @see edge_asym_verify_update
 * @see edge_asym_verify_final
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */ 
EDGE_EXPORT int         edge_asym_verify_init       (EDGE_ASYM_SIGN_CTX * p_context,
                                                     uint8_t * p_key, uint32_t p_keyLen,
                                                     EDGE_ASYM_SIGN_PARAM * p_signParam);
typedef     int         (*fp_edge_asym_verify_init) (EDGE_ASYM_SIGN_CTX *,
                                                     uint8_t *, uint32_t,
                                                     EDGE_ASYM_SIGN_PARAM *);

/**
 * @ingroup digisign
 * @anchor edge_asym_verify_update
 * @brief 비대칭키 전자 서명 검증 데이터 입력 함수.
 * @param p_context [in] EDGE_ASYM_SIGN_CTX * 비대칭키 전자 서명에 사용되는 context
 * @param p_data [in] uint8_t * 전자 서명  대상 평문 
 * @param p_dataLen [in] uint32_t 평문 길이 
 * @see edge_asym_verify_init
 * @see edge_asym_verify_final
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */ 
EDGE_EXPORT int         edge_asym_verify_update     (EDGE_ASYM_SIGN_CTX * p_context,
                                                     uint8_t * p_data, uint32_t p_dataLen);
typedef     int         (*fp_edge_asym_verify_update)(EDGE_ASYM_SIGN_CTX *, uint8_t *, uint32_t);

/**
 * @ingroup digisign
 * @anchor edge_asym_verify_final
 * @brief 비대칭키 전자 서명 검증 함수.
 * @param p_context [in] EDGE_ASYM_SIGN_CTX * 비대칭키 전자 서명에 사용되는 context
 * @param p_signData [in] uint8_t 전자 서명 데이터
 * @param p_signDataLen [in] uint32_t 전자 서명 데이터의 길이
 * @see edge_asym_verify_init
 * @see edge_asym_verify_update
 * @return EDGE_ERR_SUCCESS 서명 검증 성공 \n
 *      그외 실패에 따른 오류 코드 
 */ 
EDGE_EXPORT int         edge_asym_verify_final      (EDGE_ASYM_SIGN_CTX * p_context,
                                                     uint8_t * p_signData, uint32_t p_signDataLen);
typedef     int         (*fp_edge_asym_verify_final)(EDGE_ASYM_SIGN_CTX *, uint8_t *, uint32_t);

/**
 * @defgroup asymcipher 공개키 암호 (Asymmetric Cipher)
 * @ingroup asymcipher
 * @brief 공개키 암호 RSA 암/복호화를 제공한다. 인코딩 방식에 따라 OAEP, PKCS1_v15 두 가지 방식이 있으며
 *        CMVP 인증 인코딩은 OAEP이다. 
 */

/**
 * @ingroup asymcipher
 * @struct EDGE_ASYM_OAEP_PARAM
 * @anchor EDGE_ASYM_OAEP_PARAM
 * @see EDGE_ASYM_ENC_PARAM
 * @brief OAEP에 사용되는 세부사항에 대한 설정 구조체
 */
typedef struct {
    int         m_hashAlg;          /**< 메시지 축약에 사용될 HASH 알고리즘 */
    int         m_mgfHashAlg;       /**< MGF에 사용될 HASH 알고리즘 */
    uint8_t     * m_label;          /**< [optional] 추가 라벨 데이터 */
    uint32_t    m_labelLength;      /**< [optional] 추가 라벨 데이터의 길이 */
} EDGE_ASYM_OAEP_PARAM;

/**
 * @ingroup asymcipher
 * @anchor EDGE_RSA_ENC_MODE
 * @brief 인코딩 모드
 */
typedef enum
{
    EDGE_RSA_ENC_MODE_OAEP = 0,    /**< OAEP 인코딩 모드 */
    EDGE_RSA_ENC_MODE_PKCS1_v15    /**< PKCS1_v15 인코딩 모드 */
} EDGE_RSA_ENC_MODE;

/**
 * @ingroup asymcipher
 * @struct EDGE_ASYM_ENC_PARAM
 * @anchor EDGE_ASYM_ENC_PARAM
 * @brief 비대칭키 암호화에 사용되는 파라미터
 * @see EDGE_ASYM_OAEP_PARAM
 */
typedef struct {
    EDGE_RSA_ENC_MODE       m_encMode;       /**< 인코딩 모드 설정 @see EDGE_RSA_ENC_MODE */
    EDGE_ASYM_OAEP_PARAM    m_oaep;         /**< @see EDGE_ASYM_OAEP_PARAM */
} EDGE_ASYM_ENC_PARAM;

/**
 * @ingroup asymcipher
 * @anchor edge_asym_enc
 * @brief 비대칭키 (RSA) 암호화 함수 \n
 *        CVMP모드에서는 2048,3082의 키 길이만 지원된다. 
 * @param p_key [in] uint8_t * 암호화에 사용되는 RSA 키 [ASN.1 인코딩된 키]
 * @Param p_keyLen [in] uint32_t 비대칭키 길이 
 * @param p_data [in] uint8_t * 암호화 대상 평문 
 * @param p_dataLen [in] uint32_t 평문 길이 
 * @param p_outData [out] uint8_t * 암호문 
 * @param p_outDataLen [out] uint32_t * 암호문의 길이 
 * @param p_encParam [in] EDGE_ASYM_ENC_PARAM * 알고리즘에 적용할 세부 설정
 * <table>
 * <caption id="multi_row">키 길이에 따른 Hash 알고리즘 제한</caption>
 * <tr><th>키 길이
 * <th>메시지 Hash
 * <th>MGF Hash
 * <tr><td>256 byte
 * <td>SHA-224 / SHA-256
 * <td>SHA-224 / SHA-256
 * <tr><td>384 byte
 * <td>SHA-256
 * <td>SHA-256
 * </table><br>
 * <table>
 * <caption id="multi_row">키 길이와 메시지 hash에 따른 메시지 길이 및 라벨 길이 제한</caption>
 * <tr><th>키 길이
 * <th>메시지 Hash
 * <th>데이터 최대 길이
 * <th>라벨 길이
 * <tr><td rowspan="2">256 byte
 * <td>SHA-224
 * <td>192 byte
 * <td>28 byte 이하
 * <tr><td>SHA-256
 * <td>190 byte
 * <td>32 byte 이하
 * <tr><td>384 byte
 * <td>SHA-256
 * <td>318 byte
 * <td>32 byte 이하
 * </table>
 * @see EDGE_ASYM_ENC_PARAM
 * @see edge_asym_dec
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */ 
EDGE_EXPORT int         edge_asym_enc               (uint8_t * p_key, uint32_t p_keyLen,
                                                     EDGE_ASYM_ENC_PARAM * p_encParam,
                                                     uint8_t * p_data, uint32_t p_dataLen,
                                                     uint8_t * p_outData, uint32_t * p_outDataLen);
typedef     int         (*fp_edge_asym_enc)         (uint8_t *, uint32_t,
                                                     EDGE_ASYM_ENC_PARAM *,
                                                     uint8_t *, uint32_t,
                                                     uint8_t *, uint32_t *);


/**
 * @ingroup asymcipher
 * @anchor edge_asym_dec
 * @brief 비대칭키 (RSA) 복호화 함수 \n
 *        CVMP모드에서는 2048,3082의 키 길이만 지원된다. 
 * @param p_key [in] uint8_t * 복호화에 사용되는 RSA 키 [ASN.1 인코딩된 키]
 * @param p_keyLen [in] uint32_t 비대칭키 길이 
 * @param p_data [in] uint8_t * 암호문 
 * @param p_dataLen [in] uint32_t 암호문의 길이 
 * @param p_outData [out] uint8_t * 복호화된 평문
 * @param p_outDataLen [out] uint32_t * 평문의 길이 
 * @param p_encParam [in] EDGE_ASYM_ENC_PARAM * 알고리즘에 적용할 세부 설정
 * <table>
 * <caption id="multi_row">키 길이에 따른 Hash 알고리즘 제한</caption>
 * <tr><th>키 길이
 * <th>메시지 Hash
 * <th>MGF Hash
 * <tr><td>256 byte
 * <td>SHA-224 / SHA-256
 * <td>SHA-224 / SHA-256
 * <tr><td>384 byte
 * <td>SHA-256
 * <td>SHA-256
 * </table><br>
 * <table>
 * <caption id="multi_row">키 길이와 메시지 hash에 따른 메시지 길이 및 라벨 길이 제한</caption>
 * <tr><th>키 길이
 * <th>메시지 Hash
 * <th>데이터 최대 길이
 * <th>라벨 길이
 * <tr><td rowspan="2">256 byte
 * <td>SHA-224
 * <td>192 byte
 * <td>28 byte 이하
 * <tr><td>SHA-256
 * <td>190 byte
 * <td>32 byte 이하
 * <tr><td>384 byte
 * <td>SHA-256
 * <td>318 byte
 * <td>32 byte 이하
 * </table>
 * @see EDGE_ASYM_ENC_PARAM
 * @see edge_asym_enc
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */ 
EDGE_EXPORT int         edge_asym_dec               (uint8_t * p_key, uint32_t p_keyLen,
                                                     EDGE_ASYM_ENC_PARAM * p_encParam,
                                                     uint8_t * p_data, uint32_t p_dataLen,
                                                     uint8_t * p_outData, uint32_t * p_outDataLen);
typedef     int         (*fp_edge_asym_dec)         (uint8_t *, uint32_t,
                                                     EDGE_ASYM_ENC_PARAM *,
                                                     uint8_t *, uint32_t,
                                                     uint8_t *, uint32_t *);

/**
 * @ingroup digisign
 * @struct EDGE_ASYM_KEY_PARAM
 * @anchor EDGE_ASYM_KEY_PARAM
 * @see EDGE_DOMAIN_PARAM
 * @brief 비대칭키 생성 또는 키쌍 검증에 사용되는 세부 정보를 담은 구조체
 */
typedef struct {
    int             m_algorithm;                /**< 비대칭키 알고리즘 */
    struct {
        uint32_t    m_exponent;             /**< RSA exponent 값 */
        uint32_t    m_bits;                 /**< RSA 키 bit 값 */
    } rsa;

    struct { // domain param
        uint32_t            m_reqGenParam;  /**< DSA키 생성시 도메인 파라미터를 생성하고자 할 경우 사용 [사용:1, 사용안함:0]*/
        uint32_t            m_pBitLength;   /**< 도메인 파라미터 생성시 P의 비트 길이 */
        uint32_t            m_qBitLength;   /**< 도메인 파라미터 생성시 Q의 비트 길이 */
        EDGE_DOMAIN_PARAM   m_param;        /**< 도메인 파라미터 */
    } dsa;
} EDGE_ASYM_KEY_PARAM;

/**
 * @ingroup digisign
 * @anchor edge_asym_gen_keypair
 * @brief 비대칭 알고리즘에 따른 비대칭 키 생성 함수 (RSA의 키는 ASN.1 인코딩되어 있는 형태로 생성된다) \n
 *        생성되는 키 길이에 따라 시간이 오래 걸릴 수 있다. 
 * @param p_publicKey [out] uint8_t * 비대칭키의 공개키 데이터
 * @param p_publicKeyLen [out] uint32_t * 공개키의 길이
 * @param p_privateKey [out] uint8_t * 비대칭키의 개인키 데이터
 * @param p_privateKeyLen [out] uint32_t * 개인키의 길이
 * @param p_param [in] EDGE_ASYM_KEY_PARAM * 알고리즘에 따른 세부 정보 구조체 
 * @remark - EDGE_ASYM_DOMAIN_PARAM 생성시 p_publicKey, p_privatekey는 사용되지 않는다. 
 *         - EDGE_ASYM_DSA (DH용 키생성) 생성시 Domain Param을 생성할 수도 있고 기존 Domain Param을 사용 할 수도 있다. 
 *         - RSA 키 생성 결과 PKCS#1(ASN.1 type RSAPrivateKey, ASN.1 type RSAPublicKey)
 * @see edge_asym_verify_keypair
 * @see EDGE_ASYM_KEY_PARAM
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */ 
EDGE_EXPORT int         edge_asym_gen_keypair           (uint8_t * p_publicKey, uint32_t * p_publicKeyLen,
                                                         uint8_t * p_privateKey, uint32_t * p_privateKeyLen,
                                                         EDGE_ASYM_KEY_PARAM * p_param);
typedef     int         (*fp_edge_asym_gen_keypair)     (uint8_t *, uint32_t *,
                                                         uint8_t *, uint32_t *,
                                                         EDGE_ASYM_KEY_PARAM *);

/**
 * @ingroup digisign
 * @anchor edge_asym_verify_keypair
 * @brief 비대칭 알고리즘에 따른 비대칭 키쌍 검증 함수. 입력된 키쌍이 유효한지 검증한다.
 * @param p_publicKey [in] uint8_t * 비대칭키의 공개키 데이터
 * @param p_publicKeyLen [in] uint32_t 공개키의 길이
 * @param p_privateKey [in] uint8_t * 비대칭키의 개인키 데이터
 * @param p_privateKeyLen [in] uint32_t 개인키의 길이
 * @param p_param [in] EDGE_ASYM_KEY_PARAM * 알고리즘에 따른 세부 정보 구조체 
 * @remark - EDGE_ASYM_DOMAIN_PARAM 검증시 Domain param의 유효성을 검증한다. 
 * @see edge_asym_gen_keypair
 * @see EDGE_ASYM_KEY_PARAM
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */ 
EDGE_EXPORT int         edge_asym_verify_keypair        (uint8_t * p_publicKey, uint32_t  p_publicKeyLen,
                                                         uint8_t * p_privateKey, uint32_t  p_privateKeyLen,
                                                         EDGE_ASYM_KEY_PARAM * p_param);
typedef     int         (*fp_edge_asym_verify_keypair)  (uint8_t *, uint32_t,
                                                         uint8_t *, uint32_t,
                                                         EDGE_ASYM_KEY_PARAM *);

#define EDGE_KEYAGREEMENT                               60000
#define EDGE_KEYAGREEMENT_ID_DH                         (EDGE_KEYAGREEMENT + 100)
#define EDGE_KEYAGREEMENT_ID_ECDH                       (EDGE_KEYAGREEMENT + 200)

/**
 * @defgroup keyagree 키 설정(Key Agreement)
 * @ingroup keyagree
 * @brief 키 설정 지원 함수로. DH와 ECDH를 지원한다.\n
 *        단독으로 사용되지 않고 전자서명의 edge_asym_gen_keypair와 함께 사용된다. \n
 *  ex> ECDH_B233을 사용하고자 하는 경우 Algorighm ID : EDGE_KEYAGREEMENT_ID_ECDH + EDGE_ASYM_ID_ECC_B233
 * @see edge_asym_gen_keypair
 */ 

/**
 * @ingroup keyagree
 * @anchor edge_keyagreement
 * @brief 키토큰을 생성하는 과정은 edge_asym_gen_keypair를 이용해 생성하고 그 이후 공유 비밀 값을 연산하는 함수이다. 
 * @param p_algorithm [in] int 키 설정에 사용되는 알고리즘
 * @param p_param [in] EDGE_DOMAIN_PARAM * EDGE_KEYAGREEMENT_ID_DH를 사용하는 경우에만 사용한다. 도메인 파라미터
 * @param p_public [in] uint8_t * 외부로부터 전달 받은 키토큰 (공개키)
 * @param p_publicLen [in] uint32_t 외부 키토큰의 길이 
 * @param p_private [in] uint8_t * 내부에 생성한 키토큰 (개인키)
 * @param p_privateLen [in] uint32_t 내부 키토큰의 길이
 * @param p_secret [out] uint8_t * 공유 비밀 값 
 * @param p_secretLen [out] uint32_t * 공유 비밀 값의 길이
 * @see edge_asym_gen_keypair
 * @return EDGE_ERR_SUCCESS 성공 \n
 *      그외 실패에 따른 오류 코드 
 */
EDGE_EXPORT int         edge_keyagreement               (int p_algorithm,
                                                         EDGE_DOMAIN_PARAM * p_param,
                                                         uint8_t * p_public, uint32_t p_publicLen,
                                                         uint8_t * p_private, uint32_t p_privateLen,
                                                         uint8_t * p_secret, uint32_t * p_secretLen);
typedef     int         (*fp_edge_keyagreement)         (int,
                                                         EDGE_DOMAIN_PARAM *,
                                                         uint8_t *, uint32_t,
                                                         uint8_t *, uint32_t,
                                                         uint8_t *, uint32_t *);

typedef struct _cvmp_symfp_ {
    fp_edge_crypto_init                     edge_crypto_init;
    fp_edge_crypto_get_version              edge_crypto_get_version;
    fp_edge_crypto_change_mode              edge_crypto_change_mode;
    fp_edge_crypto_get_status               edge_crypto_get_status;
    fp_edge_crypto_zeroize                  edge_crypto_zeroize;
    fp_edge_random_byte                     edge_random_byte;
    fp_edge_crypto_final                    edge_crypto_final;
    fp_edge_crypto_cmvp_selftest            edge_crypto_cmvp_selftest;
    fp_edge_enc                             edge_enc;
    fp_edge_dec                             edge_dec;
    fp_edge_ctx_new                         edge_ctx_new;
    fp_edge_ctx_reset                       edge_ctx_reset;
    fp_edge_ctx_free                        edge_ctx_free;
    fp_edge_enc_init                        edge_enc_init;
    fp_edge_enc_update                      edge_enc_update;
    fp_edge_enc_final                       edge_enc_final;
    fp_edge_dec_init                        edge_dec_init;
    fp_edge_dec_update                      edge_dec_update;
    fp_edge_dec_final                       edge_dec_final;
    fp_edge_gcm_enc                         edge_gcm_enc;
    fp_edge_gcm_dec                         edge_gcm_dec;
    fp_edge_ccm_enc                         edge_ccm_enc;
    fp_edge_ccm_dec                         edge_ccm_dec;
    fp_edge_hash                            edge_hash;
    fp_edge_hash_ctx_new                    edge_hash_ctx_new;
    fp_edge_hash_ctx_reset                  edge_hash_ctx_reset;
    fp_edge_hash_ctx_free                   edge_hash_ctx_free;
    fp_edge_hash_init                       edge_hash_init;
    fp_edge_hash_update                     edge_hash_update;
    fp_edge_hash_final                      edge_hash_final;
    fp_edge_mac                             edge_mac;
    fp_edge_mac_ctx_new                     edge_mac_ctx_new;
    fp_edge_mac_ctx_reset                   edge_mac_ctx_reset;
    fp_edge_mac_ctx_free                    edge_mac_ctx_free;
    fp_edge_mac_init                        edge_mac_init;
    fp_edge_mac_update                      edge_mac_update;
    fp_edge_mac_final                       edge_mac_final;
    fp_edge_asym_sign                       edge_asym_sign;
    fp_edge_asym_verify                     edge_asym_verify;
    fp_edge_asym_sign_ctx_new               edge_asym_sign_ctx_new;
    fp_edge_asym_sign_ctx_reset             edge_asym_sign_ctx_reset;
    fp_edge_asym_sign_ctx_free              edge_asym_sign_ctx_free;
    fp_edge_asym_sign_init                  edge_asym_sign_init;
    fp_edge_asym_sign_update                edge_asym_sign_update;
    fp_edge_asym_sign_final                 edge_asym_sign_final;
    fp_edge_asym_verify_init                edge_asym_verify_init;
    fp_edge_asym_verify_update              edge_asym_verify_update;
    fp_edge_asym_verify_final               edge_asym_verify_final;
    fp_edge_asym_enc                        edge_asym_enc;
    fp_edge_asym_dec                        edge_asym_dec;
    fp_edge_asym_gen_keypair                edge_asym_gen_keypair;
    fp_edge_asym_verify_keypair             edge_asym_verify_keypair;
    fp_edge_keyagreement                    edge_keyagreement;
} EDGE_CMVP_SYM_HANDLE;

#ifdef __cplusplus
}
#endif

#endif //__EDGE_CRYPTO_H__
