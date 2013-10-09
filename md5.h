/**
 * \file md5.h
 * \brief Context definitions and function prototypes for the
 *   MD5 hash function.
 * \author Jouni Korhonen
 * \version 0.1 (initial)
 * \date 2013-10-8
 * \copyright Not GPL
 */

#ifndef _md5_h_included
#define _md5_h_included

#include <stdint.h>
#include "algorithm_types.h"

/* */

#define MD5_BLK_SIZE   64
#define MD5_BLK_MASK   63
#define MD5_HSH_SIZE   16

/* Basic inplace block MD5 calculation */

typedef struct md5_context_s {
	crypto_context hdr;
	int64_t index;      /* number of octets processed so far */
    uint32_t H[4];
    uint8_t buf[MD5_BLK_SIZE];
} md5_context_t;

/**
 * \brief Prototypes for MD5 calculation. 
 *
 */

crypto_context *md5_alloc( void );
crypto_context *md5_init( md5_context_t * );

#endif /* _md5_h_included */
