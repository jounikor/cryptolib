/**
 * \file sha2.h
 * \brief Context definitions and function prototypes for the
 *   SHA-256 and SHA-512 hash functions.
 * \author Jouni Korhonen
 * \version 0.1 (initial)
 * \date 2013-10-3
 * \copyright Not GPL
 */

#ifndef _sha2_h_included
#define _sha2_h_included

#include <stdint.h>
#include "algorithm_types.h"

/* */

padded message a multiple of 512 for SHA-224 and SHA-256 or a
   multiple of 1024 for SHA-384 and SHA-512.

#define SHA224_BLK_SIZE		64
#define SHA256_BLK_SIZE		64
#define SHA384_BLK_SIZE		128
#define SHA512_BLK_SIZE		128
#define SHA224_BLK_MASK		63
#define SHA256_BLK_MASK		63
#define SHA384_BLK_MASK		127
#define SHA512_BLK_MAsK		127

/* Basic inplace block SHA-2 calculation */

typedef struct {
	int64_t index;      /* number of octets processed so far */
    uint32_t H[5];
    uint8_t buf[SHA2_BLK256_SIZE];	/* lets take the maximum */
} sha2_context;

/**
 * \brief Prototypes for SHA-1 calculation. 
 *
 */

crypto_context *sha2_alloc( void );
crypto_context *sha2_init( sha2_context * );

#endif /* _sha1_h_included */
