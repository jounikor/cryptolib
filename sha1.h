/**
 * \file sha1.h
 * \brief Context definitions and function prototypes for the
 *   SHA-1 hash function.
 * \author Jouni Korhonen
 * \version 0.1 (initial)
 * \date 2013-9-7
 * \copyright Not GPL
 */

#ifndef _sha1_h_included
#define _sha1_h_included

#include <stdint.h>
#include "algorithm_types.h"

/* */

#define SHA1_BLK_SIZE   64
#define SHA1_BLK_MASK   63
#define SHA1_HSH_SIZE   20

/* Basic inplace block SHA-1 calculation */

typedef struct sha1_context_s {
	crypto_context hdr;
	int64_t index;      /* number of octets processed so far */
    uint32_t H[5];
    uint8_t buf[SHA1_BLK_SIZE];
} sha1_context;

/**
 * \brief Prototypes for SHA-1 calculation. 
 *
 */

crypto_context *sha1_alloc( void );
crypto_context *sha1_init( sha1_context * );

#endif /* _sha1_h_included */
