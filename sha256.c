/**
 * \file sha2.c
 * \brief A simple and memory efficient implementation of the
 *   SHA-256 and SHA-224 digests. The implementation is based on the RFC6234.
 *   Only the very primitive interface to calculate a digest is provided
 *   for an arbitrary size input. Also input varying length blocks are
 *   supported.
 * \author Jouni Korhonen
 * \version 0.1 (initial)
 * \date 2013-10-3
 * \copyright Not GPL
 */

#include <stdio.h>
#include <stdlib.h>

#include <memory.h>
#include <assert.h>
#include "sha256.h"
#include "crypto_error.h"

/* potential candidate for inline asm */
#define ROR(n,w) (((w) > (n)) | ((w) << (32-(n))))
#define LSR(n,w) ((w) >> (n))
#define MSK(n) (n & 0xf)

#if 0

SHA-224 & SHA-256

CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)

/*

  Padding for SHA-224 & SHA-256:
  	( L + 1 + K ) mod 512 = 448

*/



/* SHA-224 & 256 constants: */

static const uint32_t k256[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#endif


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

static void sha256_update_block( sha256_context_t *ctx ) {
    uint32_t W[16];
    uint32_t A = ctx->H[0];
    uint32_t B = ctx->H[1];
    uint32_t C = ctx->H[2];
    uint32_t D = ctx->H[3];
    uint32_t E = ctx->H[4];
    uint32_t F = ctx->H[5];
    uint32_t G = ctx->H[6];
    uint32_t H = ctx->H[7];


    int i;

    /* intialize the W[].. 16 first long words */

    for (i = 0; i < 16; i++) {
        W[i] = getlong(ctx->buf + i*4);
    }
    /* method 2 from RFC3174 */
    for (i = 16; i < 64; i++) {
		uint32_t s0, s1;
/*
 *    for i from 16 to 63
 *		s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
 *		s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
 *		w[i] := w[i-16] + s0 + w[i-7] + s1
 */

		s0 = ROR();


    }

    ctx->H[0] += A;
    ctx->H[1] += B;
    ctx->H[2] += C;
    ctx->H[3] += D;
    ctx->H[4] += E;
    ctx->H[5] += F;
    ctx->H[6] += G;
    ctx->H[7] += H;
}


/**
 * \brief Initialize the SHA-1 context for streamed hash
 *   calculation.
 *
 * \paramm ctx A pointer to the sha1_context.
 */

static int sha256_reset( crypto_context *hdr, ... ) {
	/* Note that we must not override the hdr->context value.. */

	sha1_context *ctx = (sha256_context_t *)hdr;
	ctx->index = 0;

    /* Initialize intermediate hash values */
	ctx->H[0] = 0x6a09e667;
	ctx->H[0] = 0xbb67ae85;
	ctx->H[0] = 0x3c6ef372;
	ctx->H[0] = 0xa54ff53a;
	ctx->H[0] = 0x510e527f;
	ctx->H[0] = 0x9b05688c;
	ctx->H[0] = 0x1f83d9ab;
	ctx->H[0] = 0x5be0cd19;
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

static void sha256_update( crypto_context *hdr, const void *buf, int len ) {
    sha1_context *ctx = (sha1_context *)hdr;
	int pos = 0;
    uint8_t *b = (uint8_t *)buf;

    assert(ctx);
    assert(len >= 0);

    while (len > 0) {
        int idx = ctx->index & SHA256_BLK_MASK;
        int sze = SHA256_BLK_SIZE-idx;

        if (sze > len) {
            sze = len;
        }

        memcpy(ctx->buf+idx,b+pos,sze);
        len -= sze;
        pos += sze;
        ctx->index += sze;
        
        if (idx+sze == SHA256_BLK_SIZE) {
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

static void sha256_finish( crypto_context *hdr, uint8_t *out ) {
	sha1_context *ctx = (sha1_context *)hdr;
	int idx = ctx->index & SHA256_BLK_MASK;
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

static void sha256_free( crypto_context *ctx ) {
	if (ctx) {
		free(ctx);
	}
}

static void sha256_free_dummy( crypto_context *ctx ) {
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

crypto_context *sha256_alloc( void ) {
	crypto_context *ctx = malloc(sizeof(sha256_context_t));

	if (ctx == NULL) {
		return NULL;
	}

	sha256_init((sha256_context_t *)ctx);
	ctx->free = sha256_free;
	return ctx;
}

/**
 * \brief Initialize sha1_context when located in a heap.
 *
 * \param stx A pointer to the SHA1 context to initialize.
 *
 * \return A pointer to crypto_context (which points to the
 *   input parameter sha1_context.
 */

crypto_context *sha256_init( sha256_context_t *stx ) {
	crypto_context *ctx = (crypto_context *)stx;
	memset(ctx,0,sizeof(sha1_context));
	
	ctx->algorithm = TEE_ALG_SHA2;
	ctx->size = SHA256_HSH_SIZE << 3;
	ctx->block_size = SHA256_BLK_SIZE;
	
	ctx->reset = sha256_reset;
	ctx->update = sha256_update;
	ctx->finish = sha256_finish;
	ctx->free = sha256_free_dummy();
	return ctx;
}



/**
 * \brief Get the memory size to embed a crypto context with SHA-1
 *
 * \return Number of octets required.
 */

size_t sha256_context_size( void ) {
	return sizeof(sha256_context_t);
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
