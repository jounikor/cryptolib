/**
 * \file md5.c
 * \brief A simple and memory efficient implementation of the
 *   MD5 digest. The implementation is based on the RFC121 but
 *   mostly copy-pasted from wiki :) Only the very primitive
 *   interface to calculate a digest is provided for an
 *   arbitrary size input. Also input varying length blocks are
 *   supported.
 * \author Jouni Korhonen
 * \version 0.1 (initial)
 * \date 2013-10-8
 * \copyright Not GPL
 */

#include <stdio.h>
#include <stdlib.h>

#include <memory.h>
#include <assert.h>
#include "md5.h"
#include "crypto_error.h"

/* constants .. */

static const uint32_t k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
 
/* r specifies the per-round shift amounts */
static const uint8_t r[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};


/* potential candidate for inline asm */
#define ROL(n,w) (((w) << n) | ((w) >> (32-n)))

/**
 * \brief Extract a LITTLE_ENDIAN unsigned long word out of the buffer.
 *
 * \param b A pointer to the buffer. The buffer must have
 *   at least 4 octets of space.
 *
 * \return The extracted unsigned long word.
 */

static inline uint32_t getlong( uint8_t *b ) {
    uint32_t l = *b++;
    l |= *b++ << 8;
    l |= *b++ << 16;
    l |= *b++ << 24;
    return l;
}

/**
 * \brief Insert a LITTLE_ENDIAN unsigned unsigned long into the buffer. 
 *
 * \param b A pointer to the output buffer. The buffer must have
 *   at least 4 octets of space.
 * \param l The unsigned long word to insert.
 *
 * \return A pointer to the buffer immediately following the newly
 *   inserted unsigned long word.
 */

static inline uint8_t *putlong( uint8_t *b, uint32_t l ) {
    *b++ = l;
    *b++ = l >> 8;
    *b++ = l >> 16;
    *b++ = l >> 24;
    return b;
}

/**
 * \brief Update the MD5 hash value. The implementation is based
 *   on the RFC1321, i.e. the memory efficient version.
 *
 * \param ctx A pointer to the md5_context.
 *
 * \return Nothing.
 */

static void md5_update_block( md5_context_t *ctx ) {
    uint32_t W[16];
    uint32_t f, g;
    uint32_t A = ctx->H[0];
    uint32_t B = ctx->H[1];
    uint32_t C = ctx->H[2];
    uint32_t D = ctx->H[3];
    uint32_t i;

    /* intialize the W[].. 16 first long words */

    for (i = 0; i < 16; i++) {
        W[i] = getlong(ctx->buf + i*4);
    }
    for (i = 0; i < 64; i++) {
        uint32_t t;

        if (i < 16) {
            f = (B & C) | ((~B) & D);
            g = i;
        } else if (i < 32) {
            f = (D & B) | ((~D) & C);
            g = (5*i + 1) & 0xf; /* % 16; */
        } else if (i < 48) {
            f = B ^ C ^ D;
            g = (3*i + 5) & 0xf; /* % 16; */
        } else {
            f = C ^ (B | (~D));
            g = (7*i) & 0xf; /* % 16; */
        }

        t = D;
        D = C;
        C = B;
        B = B + ROL((r[i]), (A + f + k[i] + W[g]));
        A = t;
    }

    ctx->H[0] += A;
    ctx->H[1] += B;
    ctx->H[2] += C;
    ctx->H[3] += D;
}


/**
 * \brief Initialize the MD5 context for streamed hash
 *   calculation.
 *
 * \paramm ctx A pointer to the md5_context.
 */

static int md5_reset( crypto_context *hdr, ... ) {
	/* Note that we must not override the hdr->context value.. */
	
    md5_context_t *ctx = (md5_context_t *)hdr;
	ctx->index = 0;

    /* Initialize intermediate hash values */
    ctx->H[0] = 0x67452301;
    ctx->H[1] = 0xEFCDAB89;
    ctx->H[2] = 0x98BADCFE;
    ctx->H[3] = 0x10325476;

	return CRYPTO_SUCCESS;
}


/**
 * \brief Update the hash value. This function can be called multiple times.
 *
 * \param ctx A pointer to the md5_context. The context must have been
 *   initialized prior calling this function, otherwise the result is
 *   unpredictable.
 * \param buf A pointer to input octet buffer.
 * \param len The length of the input buffer. Must be greater or equal to 0.
 *
 * \return Nothing.
 */

static void md5_update( crypto_context *hdr, const void *buf, int len ) {
    md5_context_t *ctx = (md5_context_t *)hdr;
	int pos = 0;
    uint8_t *b = (uint8_t *)buf;

    while (len > 0) {
        int idx = ctx->index & MD5_BLK_MASK;
        int sze = MD5_BLK_SIZE-idx;

        if (sze > len) {
            sze = len;
        }

        memcpy(ctx->buf+idx,b+pos,sze);
        len -= sze;
        pos += sze;
        ctx->index += sze;
        
        if (idx+sze == MD5_BLK_SIZE) {
            md5_update_block( ctx );
        }
    }
}

/**
 * \brief Return the MD5 hash of the input data so far. Note 
 *   that calling this function resets the context.
 *
 * \param ctx A pointer to the MD5 context.
 * \param hsh A pointer to a buffer of size MD5_HSH_SIZE.
 *   The output MD5 hash is in little endian.
 * \return Nothing.
 */

static void md5_finish( crypto_context *hdr, uint8_t *out ) {
	md5_context_t *ctx = (md5_context_t *)hdr;
	int idx = ctx->index & MD5_BLK_MASK;
    int64_t flen = ctx->index * 8;
    int32_t hlen = flen >> 32;
    int32_t llen = flen;

    ctx->buf[idx++] = 0x80;
    
    if (idx > 56) {
        while (idx < MD5_BLK_SIZE) {
            ctx->buf[idx++] = 0;
        }
        md5_update_block(ctx);
        idx = 0;
    }

    while (idx < MD5_BLK_SIZE-8) { 
        ctx->buf[idx++] = 0;
    }
    
    putlong(putlong(ctx->buf+idx,llen),hlen);
    md5_update_block(ctx);

    for (idx = 0; idx < 4; idx++) {
        out = putlong(out,ctx->H[idx]);
    }
}

/**
 * \brief Free the md5_context_t initialized and allocates using md5_init().
 *
 * \param ctx A pointer to the MD5 context.
 *
 * \return Nothing.
 */

static void md5_free( crypto_context *ctx) {
	if (ctx) {
		free(ctx);
	}
}

static void md5_free_dummy( crypto_context *ctx) {
}

/**
 * \brief Allocate and initialize the minumum of the MD5 context.
 *   This is supposed to be the only exported function.
 *
 * \param  
 * \param
 *
 * \return A pointer to the allocated and minimally intialized md5_context.
 *   NULL if the allocation failed.
 */

crypto_context *md5_alloc( void ) {
	crypto_context *ctx = malloc(sizeof(md5_context_t));

	if (ctx == NULL) {
		return NULL;
	}

	md5_init((md5_context_t *)ctx);
	ctx->free = md5_free;
	return ctx;
}

/**
 * \brief Initialize md5_context_t when located in a heap.
 *
 * \param stx A pointer to the MD5 context to initialize.
 *
 * \return A pointer to crypto_context (which points to the
 *   input parameter md5_context.
 */

crypto_context *md5_init( md5_context_t *stx ) {
	crypto_context *ctx = (crypto_context *)stx;
	memset(ctx,0,sizeof(md5_context_t));
	
	ctx->algorithm = TEE_ALG_MD5;
	ctx->size = MD5_HSH_SIZE << 3;
	ctx->block_size = MD5_BLK_SIZE;
	
	ctx->reset = md5_reset;
	ctx->update = md5_update;
	ctx->finish = md5_finish;
	ctx->free = md5_free_dummy;
	return ctx;
}



/**
 * \brief Get the memory size to embed a crypto context with SHA-1
 *
 * \return Number of octets required.
 */

size_t md5_context_size( void ) {
	return sizeof(md5_context_t);
}


#if !defined(PARTOFLIBRARY)
int main( int argc, char** argv )
{
    int n;
    crypto_context *ctx = md5_alloc();
    uint8_t hash[MD5_HSH_SIZE];
	
	ctx->reset(ctx);
    ctx->update(ctx,argv[1],strlen(argv[1]));
	ctx->finish(ctx,hash);


    for (n = 0; n < MD5_HSH_SIZE; n++) {
        printf("%02x",hash[n]);
    }
    printf("\n");

	ctx->reset(ctx);
    ctx->update(ctx,argv[1],strlen(argv[1]));
	ctx->finish(ctx,hash);
    for (n = 0; n < MD5_HSH_SIZE; n++) {
        printf("%02x",hash[n]);
    }
    printf("\n");

	ctx->free(ctx);

    return 0;
}
#endif
