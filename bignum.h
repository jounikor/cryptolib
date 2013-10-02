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

#define BM_MAX_SIZE  32	/**< Maximum 1024-bit numbers */
#define BM_STATIC_ALLOC	/**< Undefine this if dynamically allocated memory is needed. */

#define BM_MAX(a,b) (a) < (b) ? (b) : (a)
#define BM_RESIZE(a) (a) + BM_MAX_SIZE  /**< Resize a bignum by 1024 bits. */

/**
 * \brief Error codes that bignum functions may return. In case of errors
 *   all the functions return a negative value of the BM_ERROR_* define,
 *   not the define itself as is.
 */

#define BM_SUCCESS 0                /**< Success */
#define BM_ERROR_NOT_A_NUMBER 1     /**< The bignum type/structure contains no number. */
#define BM_ERROR_NUMBER_TOO_BIG 2   /**< The bignum operation overflew. This usually happens
                                         when static memory allocation is used. */
#define BM_ERROR_ALLOC_FAILED 3     /**< Memory allocation failed. */
#define BM_ERROR_NOT_IMPLEMENTED 4  /**< The bignum function is not implemented. */
#define BM_ERROR_DIV_BY_ZERO 5      /**< A division by zero. */
#define BM_ERROR_INTERNAL_ERROR 666 /**< Internal error within the bignum implementation.
                                         This could be because of bad input parameter or
                                         just broken implementation. */

/**
 * \brief Sign of the number..
 */

#define BM_POS 1    /**< The bignum is positive i.e. >= 0 */
#define BM_NEG -1   /**< The bignum is negative i.e. < 0 */
#define BM_NAN 0    /**< The bignum contains no number. This
                         is the initial setting for the bignum */

/**
 * \struct bm_s bignum.h bignum.h
 * \brief Bignum structure definition. The bignum is represented as
 *   an array of unsigned 32-bit numbers. 
 *
 * The bignum implementation allows either static memory allocation or
 * dynamic memory allocation. If BM_STATIC_ALLOC is defined, then static
 * memory allocation is used. Note that statically allocated bignum cannot
 * be rezised and an attemp to do so will always return an error.
 */

typedef struct bm_s {
    int sign;                   /**< Either BM_POS, BM_NEG or BM_NAN */
    int size;                   /**< The size of the current bignum in the b[] array */
    int maxs;                   /**< The maximum size of the b[] array */
#if defined(BM_STATIC_ALLOC)
    uint32_t b[BM_MAX_SIZE];    /**< The bignum array for static memory usage */
#else
    uint32_t *b;                /**< The bignum array for dynamic memory usage */
#endif
} bm_t;

typedef bm_t * bmp_t;           /**< A pointer to the bignum type */

/**
 * \brief Function prototypes implemented by the bignum.c and
 *   also exported outside the bignum.c.
 *
 */

void bm_init( bm_t * );
void bm_inits( bm_t *, ... );
void bm_done( bm_t * );
void bm_dones( bm_t *, ... );
int bm_add( bm_t *, const bm_t *, const bm_t * );
int bm_add_ui( bm_t *, uint32_t );
int bm_add_si( bm_t *, int32_t );
int bm_sub( bm_t *, const bm_t *, const bm_t * );
int bm_neg( bm_t * );
int bm_cmp( const bm_t *, const bm_t * );
int bm_cmp_ui( const bm_t *, uint32_t );
int bm_mul( bm_t *, const bm_t *, const bm_t * );
int bm_div( bm_t *, bm_t *, const bm_t *, const bm_t * );
int bm_powm( bm_t *, const bm_t *, const bm_t *, const bm_t * );
int bm_asl( bm_t *, const bm_t *, int );
int bm_asr( bm_t *, const bm_t *, int );

int bm_set_si( bm_t *, int32_t );
int bm_set_ui( bm_t *, uint32_t );
int bm_set_b( bm_t *, const unsigned char *, int );
int bm_set( bm_t *, const bm_t * );

int bm_get_b( const bm_t *, unsigned char *, int );
int bm_get_sign( const bm_t * );

#endif /* _bignum_h_included */
