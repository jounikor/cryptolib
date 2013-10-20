/**
 * \file hmac.c
 * \brief Generic HMAC calculation routines
 * \author Jouni Korhonen
 * \version 0.2
 * \date 2013-10-20
 * \warning These are just made for self educational purposes!
 * \copyright Not GPL
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <stdint.h>
#include <stdarg.h>
#include <assert.h>

#include "hmac.h"
#include "sha1.h"
#include "sha256.h"
#include "md5.h"
#include "algorithm_types.h"
#include "crypto_error.h"


/**
 * \brief Few helper functions to ease the pointer magic and casting..
 *
 * \param A pointer to an HMAC context structure, such as one
 *   allocated using hmac_alloc().
 *
 * \return A pointer to a desired structure.
 */

static crypto_context *hmac_get_hash( const crypto_context *ctx ) {
	hmac_context *htx = (hmac_context *)ctx;
	return (crypto_context *)htx->digest;
}

static hmac_context *hmac_get_hmac( const crypto_context *ctx ) {
	return (hmac_context *)ctx;
}


/**
 * \brief Finish the HMAC calculation..
 *
 * \param ctx A pointer to the HMAC context.
 * \param buf A pointer to the digest output buffer. Note that
 *   it must be large enough to hold the digest.
 * \return Nothing.
 */

static void hmac_finish( crypto_context *ctx, uint8_t *buf ) {
	hmac_context *htx = hmac_get_hmac( ctx );
	crypto_context *hsh = hmac_get_hash( ctx);

	assert(ctx);
	assert(htx);
	
	hsh->finish(hsh,buf);
	hsh->reset(hsh);
	hsh->update(hsh,htx->pad,hsh->block_size);
	hsh->update(hsh,buf,hsh->size >> 3);
	hsh->finish(hsh,buf);

	/* clear temporary things */
	memset(htx->pad,0,ctx->block_size);
}

/**
 * \brief Update the HMAC calculation..
 *
 * \param ctx A pointer to the HMAC context.
 * \param buf A pointer to input (data) buffer.
 * \param len The length of the input data.
 */

static void hmac_update( crypto_context *ctx, const void *buf, int len ) {
	hmac_context *htx = hmac_get_hmac( ctx );
	crypto_context *hsh = hmac_get_hash( ctx);

	assert(ctx);
	assert(htx);
	
	if (len > 0) {
		hsh->update(hsh,buf,len);
	}
}



/**
 * \brief Reset the hmac_context to initial state.
 *
 * \param ctx A poiter to the HMAC context to initialize.
 * \param key A pointer to the key used for HMAC.
 * \param keylen The length of the key.
 *
 * \return 0 is OK. -1 if not support for the algorithm.
 */

 static int hmac_reset( crypto_context *ctx, ... ) {
	va_list tags;
	uint32_t tag;
	uint8_t *key = NULL;
	int keylen = -1;
	int n;

	hmac_context *htx = hmac_get_hmac(ctx);
	crypto_context *hsh = hmac_get_hash(ctx);

	/* var args.. we need to read at least the key and key length */

	va_start(tags,ctx);

	while (tag = va_arg(tags,uint32_t)) {
		switch (tag) {
			case CTAG_KEY:
				key = va_arg(tags,uint8_t*);
				break;
			case CTAG_KEY_LEN:
				keylen = va_arg(tags,int);
				break;
			default:
				va_end(tags);
				return CRYPTO_ERROR_UNSUPPORTED_TAG;
		}
	}

	va_end(tags);

	if (!key || keylen < 0) {
		return CRYPTO_ERROR_UNSUPPORTED_TAG;
	}
	
	if (keylen > ctx->block_size) {
		/* if the key is longer than the hash function block size,
		 * the key is truncated into proper size by hashing it */

		hsh->reset(hsh);
		hsh->update(hsh,key,keylen);
		hsh->finish(hsh,htx->pad);
		keylen = ctx->block_size;
	} else {
		memcpy(htx->pad,key,keylen);
	}

	/* ipad.. */
	for (n = 0; n < keylen; n++) {
		htx->pad[n] ^= 0x36;
	}
	for (n = keylen; n < ctx->block_size; n++) {
		htx->pad[n] = 0x36;
	}

	hsh->reset(hsh);
	hsh->update(hsh,htx->pad,ctx->block_size);

	/* opad.. */
	for (n = 0; n < ctx->block_size; n++) {
		htx->pad[n] = htx->pad[n] ^ 0x36 ^ 0x5c;
	}

	return CRYPTO_SUCCESS;
 }

/**
 * \brief Free the context structure.
 *
 * \param[in] A pointer to a valid context structure.
 * \return None.
 */

static void hmac_free( crypto_context* ctx ) {
	hmac_context *htx = hmac_get_hmac(ctx);
    htx->digest->free(htx->digest);
    free(ctx);
}

static void hmac_free_dummy( crypto_context* ctx ) {
	hmac_context *htx = hmac_get_hmac(ctx);
    htx->digest->free(htx->digest);
}

/**
 * \brief Allocate memory for the HMAC contect. The allocation function is
 *   avare also of the used digest algorithm.
 *
 * \param alg An algorithm identifier.
 *
 * \return A pointer to the allocated context. NULL if
 *   a) out of memory or b) algorithm was unknown.
 */

crypto_context *hmac_alloc( uint32_t alg ) {
	crypto_context *ctx, *hsh;

	if ((ctx = malloc(sizeof(hmac_context))) == NULL) {
		return NULL;
	}

	/* Fix pointer magic.. this is ugly */

	switch (alg) {
	default:
	case TEE_ALG_HMAC_SHA1:
		hsh = sha1_alloc();

		if (hsh == NULL) {
			free(ctx);
			return NULL;
		}

		break;
	}

	hmac_init((hmac_context *)ctx,hsh);
	ctx->free = hmac_free;
	return ctx;
}

/**
 * \brief Initialize HMAC context when it is allocated in a heap.
 *
 * \param htx A pointer to a HMAC context to initialize. 
 * \param dtx A pointer to a digest context to include into this HMAC.
 *
 * \return A pointer to crypto_context (which points to the
 *   input parameter hmac_context.
 */

crypto_context *hmac_init( hmac_context *htx, crypto_context *dtx ) {
	crypto_context *ctx = (crypto_context *)htx;

	memset(ctx,0,sizeof(hmac_context));
	
	/* The context structures are allocated as a one blob in memory. The
	 * context and hash void pointers are then fixed to poin to the right
	 * context structures. Somewhat hacky.. brr.. should do proper allocations..
	 */
	
	/* setup hash context */
	htx->digest = dtx;

	/* fill in the minimum essentials */
	ctx->algorithm = TEE_ALG_HMAC_SHA1;
	ctx->size = dtx->size;
	ctx->block_size = dtx->block_size;
	ctx->flags = dtx->flags;

	/* input & output functions.. */
	ctx->reset = hmac_reset;
	ctx->update = hmac_update;
	ctx->finish = hmac_finish;
	ctx->free = hmac_free_dummy;

	return ctx;
}


//#if !defined(PARTOFLIBRARY)

/*

HMAC_MD5("key", "The quick brown fox jumps over the lazy dog") 
    = 0x80070713463e7749b90c2dc24911e275
HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog") 
    = 0xde7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
HMAC_SHA256("key", "The quick brown fox jumps over the lazy dog") 
    = 0xf7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8

 */

static char msg[] = "The quick brown fox jumps over the lazy dog";

static void output( uint8_t *b, int n, char *t ) {
    int m;
    printf("%s\n",t);

    for (m = 0; m < n; m++) {
		printf("%02x",b[m]);
	}
	printf("\n");
}



int main( int argc, char** argv ) {
	uint8_t digest_md5[MD5_HSH_SIZE];
	uint8_t digest_sha1[SHA1_HSH_SIZE];
	uint8_t digest_sha256[SHA256_HSH_SIZE];
	crypto_context  *hsh, *hmac_sha1, *hmac_sha256, *hmac_md5;
	int n;

	sha1_context_t sha1;
	sha256_context_t sha256;
	md5_context_t md5;
	hmac_context h_md5;
	hmac_context h_sha1;
	hmac_context h_sha256;

    hsh = md5_init(&md5);
    hmac_md5 = hmac_init(&h_md5,hsh);

    hsh = sha1_init(&sha1);
    hmac_sha1 = hmac_init(&h_sha1,hsh);
    
    hsh = sha256_init(&sha256);
    hmac_sha256 = hmac_init(&h_sha256,hsh);

	hmac_md5->reset(hmac_md5,CTAG_KEY,"key",CTAG_KEY_LEN,3,CTAG_DONE);
	hmac_sha1->reset(hmac_sha1,CTAG_KEY,"key",CTAG_KEY_LEN,3,CTAG_DONE);
	hmac_sha256->reset(hmac_sha256,CTAG_KEY,"key",CTAG_KEY_LEN,3,CTAG_DONE);

	hmac_md5->update(hmac_md5,msg,strlen(msg));
	hmac_md5->finish(hmac_md5,digest_md5);

	hmac_sha1->update(hmac_sha1,msg,strlen(msg));
	hmac_sha1->finish(hmac_sha1,digest_sha1);

	hmac_sha256->update(hmac_sha256,msg,strlen(msg));
	hmac_sha256->finish(hmac_sha256,digest_sha256);

    output(digest_md5,MD5_HSH_SIZE,"MD5:");
    output(digest_sha1,SHA1_HSH_SIZE,"SHA1:");
    output(digest_sha256,SHA256_HSH_SIZE,"SHA256:");

    hmac_md5->free(hmac_md5);
    hmac_sha1->free(hmac_sha1);
    hmac_sha256->free(hmac_sha256);

	return 0;
}

//#endif
