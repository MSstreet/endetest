#ifndef __EDGE_CRPYTO_ERROR_H__
#define __EDGE_CRPYTO_ERROR_H__

/* ERROR CODE */
#define EDGE_ERR_SUCCESS                                 0

/* Initialization */
#define EDGE_ERR_BASE                                    10000
#define EDGE_ERR_INVALID_INPUT                           (EDGE_ERR_BASE + 101)
#define EDGE_ERR_MALLOC_FAILED                           (EDGE_ERR_BASE + 102)
#define EDGE_ERR_ENTROPY                                 (EDGE_ERR_BASE + 104)
#define EDGE_ERR_ENTROPY_TEST                            (EDGE_ERR_BASE + 105)
#define EDGE_ERR_UNSUPPORTED_ALGORITHM                   (EDGE_ERR_BASE + 106)
#define EDGE_ERR_INVALID_CONTEXT                         (EDGE_ERR_BASE + 107)
#define EDGE_ERR_INVALID_KEY                             (EDGE_ERR_BASE + 108)
#define EDGE_ERR_INVALID_KEYPAIR                         (EDGE_ERR_BASE + 109)
#define EDGE_ERR_INVALID_SIGNATURE                       (EDGE_ERR_BASE + 110)
#define EDGE_ERR_INVALID_SIGNATURE_LENGTH                (EDGE_ERR_BASE + 111)

/* CMVP operation mode err */
#define EDGE_ERR_NOT_AVAILABLE_ON_CMVP_MODE              (EDGE_ERR_BASE + 113)
#define EDGE_ERR_NOT_AVAILABLE_STATUS                    (EDGE_ERR_BASE + 114)

/* Crypto not initialzied */
#define EDGE_ERR_CRYPTO_NOT_INIT                         (EDGE_ERR_BASE + 116)

/* out of range input data */
#define EDGE_ERR_OUT_OF_RANGE_INPUT                      (EDGE_ERR_BASE + 117)

/* Integrity check */
#define EDGE_ERR_INTEGRITY_LIB_NOTFOUND                  (EDGE_ERR_BASE + 201)
#define EDGE_ERR_INTEGRITY_LIB_READ                      (EDGE_ERR_BASE + 202)
#define EDGE_ERR_INTEGRITY_NOTFOUND_SIGN                 (EDGE_ERR_BASE + 203)
#define EDGE_ERR_INTEGRITY_VERIFY_SIGN                   (EDGE_ERR_BASE + 204)

#define EDGE_ERR_GENERATE_KEYPAIR                        (EDGE_ERR_BASE + 301)

/* BigInteger error */
#define EDGE_ERR_BIGINT_INTERNAL                         (EDGE_ERR_BASE + 501)

/* symmetric */
#define EDGE_ERR_SYMM                                    20000
#define EDGE_ERR_SYMM_UNSUPPORTED_MODE                   (EDGE_ERR_SYMM + 1)
#define EDGE_ERR_SYMM_UNSUPPORTED_PADDING                (EDGE_ERR_SYMM + 2)
#define EDGE_ERR_SYMM_INVALID_IV_LENGTH                  (EDGE_ERR_SYMM + 3)
#define EDGE_ERR_SYMM_INVALID_MODE_SIZE                  (EDGE_ERR_SYMM + 4)
#define EDGE_ERR_SYMM_INVALID_PADDING                    (EDGE_ERR_SYMM + 5)
#define EDGE_ERR_SYMM_CIPHER_LEN_INVALID                 (EDGE_ERR_SYMM + 6)

/* hash */
#define EDGE_ERR_HASH                                    30000
#define EDGE_ERR_HASH_UNSUPPORTED_ALGORITHM              (EDGE_ERR_HASH + 1)

/* ecc */
#define EDGE_ERR_ECC                                     40000
#define EDGE_ERR_ECC_CALC                                (EDGE_ERR_ECC + 1)
#define EDGE_ERR_ECC_ECP_RANDOM_FAIL                     (EDGE_ERR_ECC + 2)
#define EDGE_ERR_ECC_INVALID_KEY_LENGTH                  (EDGE_ERR_ECC + 4)

/* dh */
#define EDGE_ERR_DSA                                     50000
#define EDGE_ERR_DSA_GENERATE_DOMAIN_PARAM               (EDGE_ERR_DSA + 1)
#define EDGE_ERR_DSA_INVALID_DOMAIN_PARAM                (EDGE_ERR_DSA + 3)
#define EDGE_ERR_DSA_GENERATE_PRIVATE                    (EDGE_ERR_DSA + 4) 

#define EDGE_ERR_DSA_NOT_PRIME_P                         (EDGE_ERR_DSA + 5)
#define EDGE_ERR_DSA_NOT_PRIME_Q                         (EDGE_ERR_DSA + 6)
#define EDGE_ERR_DSA_NOT_MATCH_G                         (EDGE_ERR_DSA + 7)

/* rsa */
#define EDGE_ERR_RSA                                     60000
#define EDGE_ERR_RSA_MESSAGE_TOO_LONG                    (EDGE_ERR_RSA + 3)
#define EDGE_ERR_RSA_ENCODE_DATA                         (EDGE_ERR_RSA + 5)
#define EDGE_ERR_RSA_INTERNAL                            (EDGE_ERR_RSA + 7)
#define EDGE_ERR_RSA_MISMATCH_LABEL                      (EDGE_ERR_RSA + 8)
#define EDGE_ERR_RSA_MISMATCH_PADDING                    (EDGE_ERR_RSA + 9)

#define EDGE_ERR_KCDSA                                   70000
#define EDGE_ERR_KCDSA_INVALID_DOMAIN_PARAM              (EDGE_ERR_KCDSA + 1)
#define EDGE_ERR_KCDSA_GENERATE_RANDOM                   (EDGE_ERR_KCDSA + 2)

#define EDGE_ERR_AUTH_CRYPTO                             80000
#define EDGE_ERR_AUTH_CRYPTO_INVALID_INPUT_LENGTH        (EDGE_ERR_AUTH_CRYPTO + 1)
#define EDGE_ERR_AUTH_CRYPTO_INVALID_TAG_LENGTH          (EDGE_ERR_AUTH_CRYPTO + 3)
#define EDGE_ERR_AUTH_CRYPTO_VERIFY_TAG                  (EDGE_ERR_AUTH_CRYPTO + 4)

/* self test error detail */

#define EDGE_ERR_SELFTEST                                90000
#define EDGE_ERR_SELFTEST_SYMMETRIC_AES                  (EDGE_ERR_SELFTEST + 1)
#define EDGE_ERR_SELFTEST_SYMMETRIC_ARIA                 (EDGE_ERR_SELFTEST + 2)
#define EDGE_ERR_SELFTEST_SYMMETRIC_LEA                  (EDGE_ERR_SELFTEST + 3)
#define EDGE_ERR_SELFTEST_SYMMETRIC_HIGHT                (EDGE_ERR_SELFTEST + 4)
#define EDGE_ERR_SELFTEST_SYMMETRIC_SEED                 (EDGE_ERR_SELFTEST + 5)
#define EDGE_ERR_SELFTEST_HASH_HAS160                    (EDGE_ERR_SELFTEST + 6)
#define EDGE_ERR_SELFTEST_HASH_SHA1                      (EDGE_ERR_SELFTEST + 7)
#define EDGE_ERR_SELFTEST_HASH_SHA224                    (EDGE_ERR_SELFTEST + 8)
#define EDGE_ERR_SELFTEST_HASH_SHA256                    (EDGE_ERR_SELFTEST + 9)
#define EDGE_ERR_SELFTEST_HASH_SHA384                    (EDGE_ERR_SELFTEST + 10)
#define EDGE_ERR_SELFTEST_HASH_SHA512                    (EDGE_ERR_SELFTEST + 11)
#define EDGE_ERR_SELFTEST_HMAC                           (EDGE_ERR_SELFTEST + 12)
#define EDGE_ERR_SELFTEST_CMAC_AES                       (EDGE_ERR_SELFTEST + 13)
#define EDGE_ERR_SELFTEST_CMAC_ARIA                      (EDGE_ERR_SELFTEST + 14)
#define EDGE_ERR_SELFTEST_CMAC_LEA                       (EDGE_ERR_SELFTEST + 15)
#define EDGE_ERR_SELFTEST_CMAC_HIGHT                     (EDGE_ERR_SELFTEST + 16)
#define EDGE_ERR_SELFTEST_CMAC_SEED                      (EDGE_ERR_SELFTEST + 17)
#define EDGE_ERR_SELFTEST_HASH_DRBG                      (EDGE_ERR_SELFTEST + 19)
#define EDGE_ERR_SELFTEST_ASYM_CIPHER_RSA_1_5            (EDGE_ERR_SELFTEST + 21)
#define EDGE_ERR_SELFTEST_ASYM_CIPHER_RSA_OAEP           (EDGE_ERR_SELFTEST + 22)
#define EDGE_ERR_SELFTEST_ASYM_SIGN_KCDSA                (EDGE_ERR_SELFTEST + 23)
#define EDGE_ERR_SELFTEST_ASYM_SIGN_ECDSA                (EDGE_ERR_SELFTEST + 24)
#define EDGE_ERR_SELFTEST_ASYM_SIGN_EC_KCDSA             (EDGE_ERR_SELFTEST + 25)
#define EDGE_ERR_SELFTEST_ASYM_SIGN_RSA_1_5              (EDGE_ERR_SELFTEST + 26)
#define EDGE_ERR_SELFTEST_ASYM_SIGN_RSA_PSS              (EDGE_ERR_SELFTEST + 27)
#define EDGE_ERR_SELFTEST_ASYM_KEY_AGREEMENT_DH          (EDGE_ERR_SELFTEST + 29)
#define EDGE_ERR_SELFTEST_ASYM_KEY_AGREEMENT_ECDH        (EDGE_ERR_SELFTEST + 30)
#define EDGE_ERR_SELFTEST_AUTH_CRYPTO_CCM                (EDGE_ERR_SELFTEST + 31)
#define EDGE_ERR_SELFTEST_AUTH_CRYPTO_GCM                (EDGE_ERR_SELFTEST + 32)

#define EDGE_ERR_SELFTEST_KEYPAIR_KCDSA                  (EDGE_ERR_SELFTEST + 33)
#define EDGE_ERR_SELFTEST_KEYPAIR_ECDSA                  (EDGE_ERR_SELFTEST + 34)
#define EDGE_ERR_SELFTEST_KEYPAIR_EC_KCDSA               (EDGE_ERR_SELFTEST + 35)
#define EDGE_ERR_SELFTEST_KEYPAIR_RSA                    (EDGE_ERR_SELFTEST + 37)
#define EDGE_ERR_SELFTEST_KEYPAIR_DH                     (EDGE_ERR_SELFTEST + 39)
#define EDGE_ERR_SELFTEST_KEYPAIR_ECDH                   (EDGE_ERR_SELFTEST + 40)

#endif /* __EDGE_CRPYTO_ERROR_H__ */
