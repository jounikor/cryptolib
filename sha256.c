/**
 * \file sha256.c
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
#include "sha256.h"
#include "crypto_error.h"

/* potential candidate for inline asm */
#define ROR(n,w) (((w) >> (n)) | ((w) << (32-(n))))
#define LSR(n,w) ((w) >> (n))
#define MSK(n) (n & 0xf)

/* SHA-224 & 256 constants: */

static const uint32_t k[] = {
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
 * \brief Update the SHA-224 or SHA-256 hash value. This is a 
 *   memory efficient implementation using the W[] in a 
 *   circular buffer manner. Also all transformation and reading
 *   the input buffer is done in one loop.
 *
 * \param[in] ctx A pointer to the sha256_context_t.
 *
 * \return Nothing.
 */

static void sha2xx_update_block( sha256_context_t *ctx ) {
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

	for (i = 0; i < 64; i++) {
        uint32_t t1, t2, s1, ch, s0, maj;
        uint32_t w = 0;

        if (i < 16) {
            w = W[i] = getlong(ctx->buf + i*4);
        } else {
            uint32_t s0, s1, t;
#define MODI(x) (x & 0x0f)
            t = W[MODI(i-15)]; s0 = ROR(7,t) ^ ROR(18,t) ^ LSR(3,t); 
            t = W[MODI(i-2)];  s1 = ROR(17,t) ^ ROR(19,t) ^ LSR(10,t);
            w = W[MODI(i-16)] + s0 + W[MODI(i-7)] + s1;
            W[MODI(i)] = w;
#undef MODI
        }
        
        s1 = ROR(6,E) ^ ROR(11,E) ^ ROR(25,E);
        ch = (E & F) ^ (~E & G);
        t1 = H + s1 + ch + k[i] + w;

        s0 = ROR(2,A) ^ ROR(13,A) ^ ROR(22,A);
        maj = (A & (B ^ C)) ^ (B & C);  /* == (A & B) ^ (A & C)  ^ (B & C); */
        t2 = s0 + maj;
    
        H = G;
        G = F;
        F = E;
        E = D + t1;
        D = C;
        C = B;
        B = A;
        A = t1 + t2;
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
 * \brief Initialize the SHA256 context for streamed hash
 *   calculation.
 *
 * \paramm ctx A pointer to the sha1_context.
 */

static int sha2xx_reset( crypto_context *hdr, ... ) {
	/* Note that we must not override the hdr->context value.. */

	sha256_context_t *ctx = (sha256_context_t *)hdr;
	ctx->index = 0;

    if (hdr->algorithm == TEE_ALG_SHA256) {
    /* Initialize intermediate hash values for SHA-256 */
        ctx->H[0] = 0x6a09e667;
        ctx->H[1] = 0xbb67ae85;
        ctx->H[2] = 0x3c6ef372;
        ctx->H[3] = 0xa54ff53a;
        ctx->H[4] = 0x510e527f;
        ctx->H[5] = 0x9b05688c;
        ctx->H[6] = 0x1f83d9ab;
        ctx->H[7] = 0x5be0cd19;
    } else {
        /* Initialize intermediate hash values for SHA-224 */
        ctx->H[0] = 0xc1059ed8;
        ctx->H[1] = 0x367cd507;
        ctx->H[2] = 0x3070dd17;
        ctx->H[3] = 0xf70e5939;
        ctx->H[4] = 0xffc00b31;
        ctx->H[5] = 0x68581511;
        ctx->H[6] = 0x64f98fa7;
        ctx->H[7] = 0xbefa4fa4;
    }
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

static void sha2xx_update( crypto_context *hdr, const void *buf, int len ) {
    sha256_context_t *ctx = (sha256_context_t *)hdr;
	int pos = 0;
    uint8_t *b = (uint8_t *)buf;

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
            sha2xx_update_block( ctx );
        }
    }
}

/**
 * \brief Return the SHA256 hash of the input data so far. Note 
 *   that calling this function resets the context.
 *
 * \param ctx A pointer to the SHA256 context.
 * \param hsh A pointer to a buffer of size SHA256_HSH_SIZE.
 *
 * \return Nothing.
 */

static void sha2xx_finish( crypto_context *hdr, uint8_t *out ) {
	sha256_context_t *ctx = (sha256_context_t *)hdr;
	int idx = ctx->index & SHA256_BLK_MASK;
    int64_t flen = ctx->index * 8;
    int32_t hlen = flen >> 32;
    int32_t llen = flen;
    int max = hdr->algorithm == TEE_ALG_SHA224 ? 7 : 8; 

    ctx->buf[idx++] = 0x80;
    
    if (idx > 56) {
        while (idx < SHA256_BLK_SIZE) {
            ctx->buf[idx++] = 0;
        }
        sha2xx_update_block(ctx);
        idx = 0;
    }

    while (idx < SHA256_BLK_SIZE-8) { 
        ctx->buf[idx++] = 0;
    }
    
    putlong(putlong(ctx->buf+idx,hlen),llen);
    sha2xx_update_block(ctx);

    for (idx = 0; idx < max; idx++) {
        out = putlong(out,ctx->H[idx]);
    }
}

/**
 * \brief Free the sha1_context initialized and allocates using sha1_init().
 *
 * \param ctx A pointer to the SHA-224/256 context.
 *
 * \return Nothing.
 */

static void sha2xx_free( crypto_context *ctx ) {
	if (ctx) {
		free(ctx);
	}
}

static void sha2xx_free_dummy( crypto_context *ctx ) {
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
	ctx->free = sha2xx_free;
	return ctx;
}

crypto_context *sha224_alloc( void ) {
	crypto_context *ctx = malloc(sizeof(sha224_context_t));

	if (ctx == NULL) {
		return NULL;
	}

	sha224_init((sha224_context_t *)ctx);
	ctx->free = sha2xx_free;
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

static crypto_context *sha2xx_init( crypto_context *ctx, uint32_t algo ) {
	memset(ctx,0,sizeof(sha256_context_t));
	
	ctx->algorithm = algo;
	ctx->size = SHA256_HSH_SIZE << 3;
	ctx->block_size = SHA256_BLK_SIZE;
	
	ctx->reset = sha2xx_reset;
	ctx->update = sha2xx_update;
	ctx->finish = sha2xx_finish;
	ctx->free = sha2xx_free_dummy;
	return ctx;
}



crypto_context *sha256_init( sha256_context_t *stx ) {
	return sha2xx_init( (crypto_context *)stx, TEE_ALG_SHA256);
}

crypto_context *sha224_init( sha224_context_t *stx ) {
    return sha2xx_init( (crypto_context *)stx, TEE_ALG_SHA224);
}




#if !defined(PARTOFLIBRARY)
int main( int argc, char** argv )
{
    int n;
    crypto_context *ctx = sha256_alloc();
    uint8_t hash[SHA256_HSH_SIZE];
	
	ctx->reset(ctx);
    ctx->update(ctx,argv[1],strlen(argv[1]));
	ctx->finish(ctx,hash);


    for (n = 0; n < SHA256_HSH_SIZE; n++) {
        printf("%02x",hash[n]);
    }
    printf("\n");
    ctx->free(ctx);

    sha224_context_t sha224;
    ctx = sha224_init(&sha224);

	ctx->reset(ctx);
    ctx->update(ctx,argv[1],strlen(argv[1]));
	ctx->finish(ctx,hash);
    for (n = 0; n < SHA224_HSH_SIZE; n++) {
        printf("%02x",hash[n]);
    }
    printf("\n");

	ctx->free(ctx);

    return 0;
}
#endif
