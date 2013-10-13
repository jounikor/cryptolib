/**
 * \file sha256.h
 * \brief Context definitions and function prototypes for the
 *   SHA-256 and SHA-224 hash functions.
 * \author Jouni Korhonen
 * \version 0.1 (initial)
 * \date 2013-10-3
 * \copyright Not GPL
 */

#ifndef _sha256_h_included
#define _sha256_h_included

#include <stdint.h>
#include "algorithm_types.h"

#define SHA224_BLK_SIZE		64
#define SHA256_BLK_SIZE		64
#define SHA224_BLK_MASK		63
#define SHA256_BLK_MASK		63

/* Basic inplace block SHA-224/256 calculation */

typedef struct sha256_context_s {
	int64_t index;      /* number of octets processed so far */
    uint32_t H[8];		/* be prepared for all SHA-224/256
    uint8_t buf[SHA256_BLK_SIZE];	/* lets take the maximum */
} sha256_context_t;

/**
 * \brief Prototypes for SHA256 calculation. 
 *
 */

crypto_context *sha256_alloc( void );
crypto_context *sha256_init( sha256_context_t * );
crypto_context *sha224_alloc( void );
crypto_context *sha224_init( sha256_context_t * );


#endif /* _sha256_h_included */
