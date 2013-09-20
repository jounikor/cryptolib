/**
 * \file sha1.c
 * \brief A simple and memory efficient implementation of the
 *   SHA-1 digest. The implementation is based on the RFC3174
 *   method 2 example. Only the very primitive interface to
 *   calculate a digest is provided for an arbitrary size input.
 *   Also input varying length blocks is supported.
 * \author Jouni Korhonen
 * \version 0.1 (initial)
 * \date 2013-9-7
 * \copyright Not GPL
 */

#include <stdio.h>
#include <stdlib.h>

#include <memory.h>
#include <assert.h>
#include "sha1.h"
#include "crypto_error.h"

/* potential candidate for inline asm */
#define ROL(n,w) (((w) << n) | ((w) >> (32-n)))
#define MSK(n) (n & 0xf)

/**
 * \brief Extract a BIG_ENDIAN unsigned long word out of the buffer.
 *
 * \param b A pointer to the buffer. The buffer must have
 *   at least 4 octets of space.
 *
 * \return The extracted unsigned long word.
 */

static inline uint32_t getlong( uint8_t *b ) {
    uint32_t l = *b++;
    l = l << 8 | *b++;
    l = l << 8 | *b++;
    l = l << 8 | *b++;
    return l;
}

/**
 * \brief Insert a BIG_ENDIAN unsigned unsigned long into the buffer. 
 *
 * \param b A pointer to the output buffer. The buffer must have
 *   at least 4 octets of space.
 * \param l The unsigned long word to insert.
 *
 * \return A pointer to the buffer immediately following the newly
 *   inserted unsigned long word.
 */

static inline uint8_t *putlong( uint8_t *b, uint32_t l ) {
    *b++ = l >> 24;
    *b++ = l >> 16;
    *b++ = l >> 8;
    *b++ = l;
    return b;
}

/**
 * \brief Update the SHA-1 hash value. The implementation is based
 *   on the RFC3174 Method 2, i.e. the memory efficient version.
 *
 * \param ctx A pointer to the sha1_context.
 *
 * \return Nothing.
 */

static void sha1_update_block( sha1_context *ctx ) {
    uint32_t W[16];
    uint32_t A = ctx->H[0];
    uint32_t B = ctx->H[1];
    uint32_t C = ctx->H[2];
    uint32_t D = ctx->H[3];
    uint32_t E = ctx->H[4];

    int i;

    /* intialize the W[].. 16 first long words */

    for (i = 0; i < 16; i++) {
        W[i] = getlong(ctx->buf + i*4);
    }
    /* method 2 from RFC3174 */
    for (i = 0; i < 80; i++) {
        uint32_t t;
        int s = MSK(i);

        if (i >= 16) {
            W[s] = ROL(1,W[MSK(s+13)] ^ W[MSK(s+8)] ^ W[MSK(s+2)] ^ W[s]);
        }

        t = ROL(5,A) + E + W[s];

        if (i < 20) {
            t = t + 0x5A827999 + ((B & C) | (~B & D)); 
        } else if (i < 40) {
            t = t + 0x6ED9EBA1 + (B ^ C ^ D);
        } else if (i < 60) {
            t = t + 0x8F1BBCDC + ((B & C) | (B & D) | (C & D));
        } else {
            t = t + 0xCA62C1D6 + (B ^ C ^ D);
        }

        E = D;
        D = C;
        C = ROL(30,B);
        B = A;
        A = t;
    }

    ctx->H[0] += A;
    ctx->H[1] += B;
    ctx->H[2] += C;
    ctx->H[3] += D;
    ctx->H[4] += E;
}


/**
 * \brief Initialize the SHA-1 context for streamed hash
 *   calculation.
 *
 * \paramm ctx A pointer to the sha1_context.
 */

static int sha1_reset( crypto_context *hdr, ... ) {
	/* Note that we must not override the hdr->context value.. */

	assert(hdr);
	sha1_context *ctx = (sha1_context *)hdr->context;
	ctx->index = 0;

    /* Initialize intermediate hash values */
    ctx->H[0] = 0x67452301;
    ctx->H[1] = 0xEFCDAB89;
    ctx->H[2] = 0x98BADCFE;
    ctx->H[3] = 0x10325476;
    ctx->H[4] = 0xC3D2E1F0;

	return CRYPTO_SUCCESS;
}


/**
 * \brief Update the hash value. This function can be called multiple times.
 *
 * \param ctx A pointer to the sha1_context. The context must have been
 *   initialized prior calling this function, otherwise the result is
 *   unpredictable.
 * \param buf A pointer to input octet buffer.
 * \param len The length of the input buffer. Must be greater or equal to 0.
 *
 * \return Nothing.
 */

static void sha1_update( crypto_context *hdr, const void *buf, int len ) {
    sha1_context *ctx = (sha1_context *)hdr->context;
	int pos = 0;
    uint8_t *b = (uint8_t *)buf;

    assert(ctx);
    assert(len >= 0);

    while (len > 0) {
        int idx = ctx->index & SHA1_BLK_MASK;
        int sze = SHA1_BLK_SIZE-idx;

        if (sze > len) {
            sze = len;
        }

        memcpy(ctx->buf+idx,b+pos,sze);
        len -= sze;
        pos += sze;
        ctx->index += sze;
        
        if (idx+sze == SHA1_BLK_SIZE) {
            sha1_update_block( ctx );
        }
    }
}

/**
 * \brief Return the SHA-1 hash of the input data so far. Note 
 *   that calling this function resets the context.
 *
 * \param ctx A pointer to the SHA-1 context.
 * \param hsh A pointer to a buffer of size SHA1_HSH_SIZE.
 *
 * \return Nothing.
 */

static void sha1_finish( crypto_context *hdr, uint8_t *out ) {
	sha1_context *ctx = (sha1_context *)hdr->context;
	int idx = ctx->index & SHA1_BLK_MASK;
    int64_t flen = ctx->index * 8;
    int32_t hlen = flen >> 32;
    int32_t llen = flen;

    assert(ctx);

    ctx->buf[idx++] = 0x80;
    
    if (idx > 56) {
        while (idx < SHA1_BLK_SIZE) {
            ctx->buf[idx++] = 0;
        }
        sha1_update_block(ctx);
        idx = 0;
    }

    while (idx < SHA1_BLK_SIZE-8) { 
        ctx->buf[idx++] = 0;
    }
    
    putlong(putlong(ctx->buf+idx,hlen),llen);
    sha1_update_block(ctx);

#if 0
    for (idx = 0; idx < 64; idx++) {
        printf("%02x",ctx->buf[idx]);
        if (idx % 8 == 7) {
            printf("\n");
        }
    }
    printf("\n");
#endif

    for (idx = 0; idx < 5; idx++) {
        out = putlong(out,ctx->H[idx]);
    }
}

/**
 * \brief Free the sha1_context initialized and allocates using sha1_init().
 *
 * \param ctx A pointer to the SHA1 context.
 *
 * \return Nothing.
 */

static void sha1_free( crypto_context *ctx) {
	if (ctx) {
		free(ctx);
	}
}

/**
 * \brief Allocate and initialize the minumum of the SHA1 context.
 *   This is supposed to be the only exported function.
 *
 * \param  
 * \param
 *
 * \return A pointer to the allocated and minimally intialized sha1_context.
 *   NULL if the allocation failed.
 */

crypto_context *sha1_alloc( void ) {
	crypto_context *ctx = malloc(sizeof(sha1_context)+sizeof(crypto_context));

	if (ctx == NULL) {
		return NULL;
	}

	memset(ctx,0,sizeof(sha1_context)+sizeof(crypto_context));
	
	/* place the SHA1 context immediately after the crypto_context in memory */
	ctx->context = (void *)(ctx+1);

	ctx->algorithm = TEE_ALG_SHA1;
	ctx->size = SHA1_HSH_SIZE << 3;
	ctx->block_size = SHA1_BLK_SIZE;
	
	ctx->reset = sha1_reset;
	ctx->update = sha1_update;
	ctx->finish = sha1_finish;
	ctx->free = sha1_free;

	return ctx;
}

/**
 * \brief Get the memory size to embed a crypto context with SHA-1
 *
 * \return Number of octets required.
 */

size_t sha1_context_size( void ) {
	return sizeof(crypto_context)+sizeof(sha1_context);
}


#if !defined(PARTOFLIBRARY)
int main( int argc, char** argv )
{
    int n;
    crypto_context *ctx = sha1_alloc();
    uint8_t hash[SHA1_HSH_SIZE];
	
	ctx->reset(ctx);
    ctx->update(ctx,argv[1],strlen(argv[1]));
	ctx->finish(ctx,hash);


    for (n = 0; n < SHA1_HSH_SIZE; n++) {
        printf("%02x",hash[n]);
    }
    printf("\n");

	ctx->reset(ctx);
    ctx->update(ctx,argv[1],strlen(argv[1]));
	ctx->finish(ctx,hash);
    for (n = 0; n < SHA1_HSH_SIZE; n++) {
        printf("%02x",hash[n]);
    }
    printf("\n");

	ctx->free(ctx);

    return 0;
}
#endif
