/**
 * \file hmac.h
 * \brief Implementations of a number of HMAC algorithms.
 *
 *
 *
 *
 */

#ifndef _hmac_h_included
#define _hmac_h_included

#include "algorithm_types.h"
#include "sha1.h"

/* for now.. this is enough */

#define HMAC_MAX_KEY SHA1_BLK_SIZE

/* the context is now "hardcoded" for at least MD5 and SHA-1. If you
 * need more flexibility, go ahead and structure.. 
 */

typedef struct hmac_context_s {
	crypto_context hdr;
	uint8_t pad[HMAC_MAX_KEY];
	crypto_context *digest;
} hmac_context;

/**
 * \brief Generic HMAC function prototypes.
 *
 *
 *
 */

crypto_context *hmac_alloc( uint32_t );
crypto_context *hmac_init( hmac_context*, crypto_context* );

#endif /* _hmac_h_included  */
