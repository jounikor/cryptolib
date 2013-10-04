/**
 * \file sha2.c
 * \brief A simple and memory efficient implementation of the
 *   SHA-256 and SHA-512 digests. The implementation is based on the RFC6234.
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
#include "sha2.h"
#include "crypto_error.h"

/* potential candidate for inline asm */
#define ROL(n,w) (((w) << n) | ((w) >> (32-n)))
#define MSK(n) (n & 0xf)

#if 0

SHA-224 & SHA-256S

CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)

General..

ROTL^n(x) = ROTR^(w-n)(x)
ROTR^n(x) = ROTL^(w-n)(x)

Padding for SHA-224 & SHA-256:
	( L + 1 + K ) mod 512 = 448

Padding for SHA-384 & SHA-512:
	( L + 1 + K ) mod 1024 = 896

SHA-224 & 256 constants:

0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2


SHA-384 and SHA 512:

CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
BSIG0(x) = ROTR^28(x) XOR ROTR^34(x) XOR ROTR^39(x)
BSIG1(x) = ROTR^14(x) XOR ROTR^18(x) XOR ROTR^41(x)
SSIG0(x) = ROTR^1(x) XOR ROTR^8(x) XOR SHR^7(x)
SSIG1(x) = ROTR^19(x) XOR ROTR^61(x) XOR SHR^6(x)


428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc
3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118
d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2
72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694
e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65
2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5
983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4
c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70
27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df
650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b
a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30
d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8
19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8
391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3
748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec
90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b
ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178
06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b
28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c
4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817



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
	sha1_context *ctx = (sha1_context *)hdr;
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
    sha1_context *ctx = (sha1_context *)hdr;
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
	sha1_context *ctx = (sha1_context *)hdr;
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
	crypto_context *ctx = malloc(sizeof(sha1_context));

	if (ctx == NULL) {
		return NULL;
	}

	sha1_init((sha1_context *)ctx);
	ctx->free = sha1_free;
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

crypto_context *sha1_init( sha1_context *stx ) {
	crypto_context *ctx = (crypto_context *)stx;
	memset(ctx,0,sizeof(sha1_context));
	
	ctx->algorithm = TEE_ALG_SHA1;
	ctx->size = SHA1_HSH_SIZE << 3;
	ctx->block_size = SHA1_BLK_SIZE;
	
	ctx->reset = sha1_reset;
	ctx->update = sha1_update;
	ctx->finish = sha1_finish;
	ctx->free = (void(*)(crypto_context *))0;
	return ctx;
}



/**
 * \brief Get the memory size to embed a crypto context with SHA-1
 *
 * \return Number of octets required.
 */

size_t sha1_context_size( void ) {
	return sizeof(sha1_context);
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
