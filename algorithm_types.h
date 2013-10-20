/**
 * \file algorithm_types.h
 * \brief A set of defines for different crypto algorithms. The
 *   algorithm "identifications" are compatible with the Global
 *   Platform Internal Core API defines.
 * \author Jouni Korhonen
 * \version 0.1
 * \date 2013-9-7
 * \copyright Not GPL
 */

#ifndef _algorithm_types_h_included
#define _algorithm_types_h_included

struct crypto_context_s;
typedef struct crypto_context_s crypto_context;

struct crypto_context_s {
    uint32_t algorithm;
    int16_t size;
	int16_t block_size;
    uint32_t flags;

	int (*reset)(   crypto_context *, ... );
	void (*update)( crypto_context *, const void *, int );
	void (*finish)( crypto_context *, uint8_t* );
	/* free points to NULL if a context is allocated in a stack */ 
	void (*free)( crypto_context *);

	/* Context specific data follows.. */
	uint8_t private[0];
};

/**
 * \brief Tags for reset() function.
 *
 */

enum crypto_tags {
	CTAG_DONE=0,	/**< End marker for a TAG list */
	CTAG_KEY,		/**< A pointer to the key data */
	CTAG_KEY_LEN,	/**< A length of the key data */
    CTAG_HSH_ALGO,  /**< to distinguis between SHA224/256/384/512 */
};


/**
 * \brief Flags definitions.
 *
 */

#define CFLAG_STATIC_ALLOC	0x00000001	/**< All context pointers are statically allocated
										 * i.e. the free() function must not free individual
										 * contexts.. */

/**
 * \brief A rundown of digest, crypto, MAC etc algorithm identifiers.
 */

#define TEE_ALG_AES_ECB_NOPAD   0x10000010
#define TEE_ALG_AES_CBC_NOPAD   0x10000110
#define TEE_ALG_AES_CTR 0x10000210
#define TEE_ALG_AES_CTS 0x10000310
#define TEE_ALG_AES_XTS 0x10000410
#define TEE_ALG_AES_CBC_MAC_NOPAD   0x30000110
#define TEE_ALG_AES_CBC_MAC_PKCS5   0x30000510
#define TEE_ALG_AES_CMAC    0x30000610
#define TEE_ALG_AES_CCM 0x40000710
#define TEE_ALG_AES_GCM 0x40000810
#define TEE_ALG_DES_ECB_NOPAD   0x10000011
#define TEE_ALG_DES_CBC_NOPAD   0x10000111
#define TEE_ALG_DES_CBC_MAC_NOPAD   0x30000111
#define TEE_ALG_DES_CBC_MAC_PKCS5   0x30000511
#define TEE_ALG_DES3_ECB_NOPAD  0x10000013
#define TEE_ALG_DES3_CBC_NOPAD  0x10000113
#define TEE_ALG_DES3_CBC_MAC_NOPAD  0x30000113
#define TEE_ALG_DES3_CBC_MAC_PKCS5  0x30000513
#define TEE_ALG_RSASSA_PKCS1_V1_5_MD5   0x70001830
#define TEE_ALG_RSASSA_PKCS1_V1_5_SHA1  0x70002830
#define TEE_ALG_RSASSA_PKCS1_V1_5_SHA224    0x70003830
#define TEE_ALG_RSASSA_PKCS1_V1_5_SHA256    0x70004830
#define TEE_ALG_RSASSA_PKCS1_V1_5_SHA384    0x70005830
#define TEE_ALG_RSASSA_PKCS1_V1_5_SHA512    0x70006830
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1  0x70212930
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224    0x70313930
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256    0x70414930
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384    0x70515930
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512    0x70616930
#define TEE_ALG_RSAES_PKCS1_V1_5    0x60000130
#define TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1  0x60210230
#define TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224    0x60310230
#define TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256    0x60410230
#define TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384    0x60510230
#define TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512    0x60610230
#define TEE_ALG_RSA_NOPAD   0x60000030
#define TEE_ALG_DSA_SHA1    0x70002131
#define TEE_ALG_DH_DERIVE_SHARED_SECRET 0x80000032
#define TEE_ALG_MD5 0x50000001
#define TEE_ALG_SHA1    0x50000002
#define TEE_ALG_SHA224  0x50000003
#define TEE_ALG_SHA256  0x50000004
#define TEE_ALG_SHA384  0x50000005
#define TEE_ALG_SHA512  0x50000006
#define TEE_ALG_HMAC_MD5    0x30000001
#define TEE_ALG_HMAC_SHA1   0x30000002
#define TEE_ALG_HMAC_SHA224 0x30000003
#define TEE_ALG_HMAC_SHA256 0x30000004
#define TEE_ALG_HMAC_SHA384 0x30000005
#define TEE_ALG_HMAC_SHA512 0x30000006







#endif /* _algorithm_types_h_included */


