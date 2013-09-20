#ifndef _bignum_h_included
#define _bignum_h_included

/**
 * \file bignum.h
 * \brief Structure and other definitions for a minimalistic 
 *   bignum implementation.
 * \author Jouni Korhonen
 * \version 0.1
 * \date 2013-09-15
 * \copyright This in not GPL.
 *
 */

#include <stdint.h>

/**
 * \brief Defines.
 *
 */

#define BM_MAX_SIZE  32	/**< max 1024 bits numbers */
#define BM_STATIC_ALLOC	/**< undefine if dynamically allocated memory is ok */

#define BM_MAX(a,b) (a) < (b) ? (b) : (a)
#define BM_RESIZE(a) (a) * 3 / 2

/**
 * \bried Error codes that bignum functions may return.
 *
 */

#define BM_SUCCESS 0
#define BM_ERROR_NOT_A_NUMBER 1
#define BM_ERROR_NUMBER_TOO_BIG 2
#define BM_ERROR_ALLOC_FAILED 3
#define BM_ERROR_INTERNAL_ERROR 666

/**
 * \brief Sign of the number..
 *
 */

#define BM_POS 1
#define BM_NEG -1

/**
 * \struct bm_s bignum.h bignum.h
 * \brief Bignum structure definition. The bignum is represented as
 *   an array of unsigned 32-bit numbers. 
 *
 * \typedef bm_t
 * \typedef bmp_t
 */

typedef struct bm_s {
    int sign;
    int size;
    int maxs;
#if defined(BM_STATIC_ALLOC)
    uint32_t b[BM_MAX_SIZE];
#else
    uint32_t *b;
#endif
} bm_t;

typedef bm_t * bmp_t;

/**
 * \brief function prototypes..
 *
 *
 */

int bm_init( bm_t * );
void bm_done( bm_t * );
int bm_add( bm_t *, const bm_t *, const bm_t * );
int bm_sub( bm_t *, const bm_t *, const bm_t * );
int bm_neg( bm_t * );
int bm_cmp( const bm_t *, const bm_t * );
int bm_mul( bm_t *, const bm_t *, const bm_t * );
int bm_div( bm_t *, const bm_t *, const bm_t * );
int bm_mod( bm_t *, const bm_t *, const bm_t * );
int bm_powm( bm_t *, const bm_t *, const bm_t *, const bm_t * );

int bm_set_si( bm_t *, int32_t );
int bm_set_ui( bm_t *, uint32_t );
int bm_set_b( bm_t *, const unsigned char *, int );
int bm_set( bm_t *, const bm_t * );

int bm_get_b( const bm_t *, unsigned char *, int );
int bm_get_sign( const bm_t * );

#endif /* _bignum_h_included */
