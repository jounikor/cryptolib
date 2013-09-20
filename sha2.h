/**
 * \file sha2.h
 * \brief Context definitions and function prototypes for the
 *   SHA-224 and SHA-256 hash functions.
 * \author Jouni Korhonen
 * \version 0.1 (initial)
 * \date 2013-9-10
 * \copyright Not GPL
 */

#ifndef _sha2_h_included
#define _sha2_h_included

#include <stdint.h>
#include "algorithm_types.h"

/* */

#define SHA2_BLK_SIZE		64
#define SHA2_BLK_MASK		63
#define SHA2_HSH224_SIZE	28
#define SHA2_HSH256_SIZE	32


/* Basic inplace block SHA-2 calculation */

typedef struct {
	int64_t index;      /* number of octets processed so far */
    uint32_t H[5];
    uint8_t buf[SHA2_BLK256_SIZE];	/* lets take the maximum */
} sha1_context;

/**
 * \brief Prototypes for SHA-1 calculation. 
 *
 */

crypto_context *sha1_alloc( void );

#endif /* _sha1_h_included */
