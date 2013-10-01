/**
 * \file bignum.c
 * \brief Minimalistic Bignum implementation. Currently supported
 *   methods are: add, sub, mul, div, mod and exp (and exp+mod).
 *
 * \author Jouni Korhonen
 * \version 0.2
 * \date 2013-09-19
 * \copyright This is not GPL.
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "bignum.h"

/**
 * \brief A helper function to calculate the number of
 *   long words needed for an array of octets.
 *
 * \param n The number of octets.
 *
 * \return The number of needed long words.
 */

static inline get_size_in_longs( int n ) {
	return (n+sizeof(uint32_t)-1) / sizeof(uint32_t);
}

static inline uint32_t ror8( uint32_t a, int n ) {
	return (a >> n*8) | (a << (32-n*8));
}

static inline uint32_t rol8( uint32_t a, int n ) {
	return (a << n*8) | (a >> (32-n*8));
}

static int bm_is_zero( const bm_t * a ) {
	int n;

	for (n = 0; n < a->size; n++) {
		if (a->b[n]) {
			return 0;
		}
	}
	return 1;
}

static void bm_trim( bm_t *r, int n ) {
	assert(n > 0);

	while (r->b[n-1] == 0) {
		n--;
	}
	r->size = n;
}

/**
 * \brief Set bignum size.
 *
 *
 */

static int bm_set_size( bm_t *a, int s ) {
    int n;

#if !defined(BM_STATIC_ALLOC)
    while (s > a->maxs) {
        if ((n = bm_resize(a)) != BM_SUCCESS) {
            return n;
        }
    }
#else
    if (a->maxs > 0 && s > a->maxs) {
        return -BM_ERROR_NUMBER_TOO_BIG;
    } else {
        a->maxs = BM_MAX_SIZE;
    }
#endif
    a->size = s;
    return BM_SUCCESS;
}


/**
 * \brief Resize i.e. grow the internal buffer to hold the
 *   bignum. In case of statically allocated memory this
 *   function always fails.
 *
 * \param A pointer to a bignum to resize.
 * \return BM_SUCCESS if ok, error otherwise.
 */

static int bm_resize( bm_t *r ) {
#if defined(BM_STATIC_ALLOC)
	if (r->maxs == 0) {
        r->maxs = BM_MAX_SIZE;
    } else {    
        return -BM_ERROR_NUMBER_TOO_BIG;
    }
#else
	if ((r->b = realloc(r->b,BM_RESIZE(r->maxs))) == NULL) {
		return -BM_ERROR_ALLOC_FAILED;
	}

	r->maxs = BM_RESIZE(r->maxs);
#endif
	return BM_SUCCESS;
}

/**
 * \brief Initialize a bignum. By default the bignum is set
 *  to a "positive zero".
 *
 * \param m A pointer to a bignum structure.
 * \return BM_SUCCESS if OK.
 */

void bm_init( bm_t *m ) {
    m->size = 0;
    m->sign = BM_NAN;
    m->maxs = 0;
#if !defined(BM_STATIC_ALLOC)
    m->b = NULL;
#endif
}



/**
 * \brief Free memory reserver for the bignum structure.
 *
 * \param m A pointer to the bignum structure.
 * \return Nothing.
 */

void bm_done( bm_t *m ) {
#if !defined(BM_STATIC_ALLOC)
    if (m->b) {
        free(m->b);
        m->b = NULL;
    }
#endif
    m->size = 0;
    m->maxs = 0;
}

/**
 * \brief Sub two bignumers and neglect the sign. Note that the output
 *   bignumber must not be any of the input bignumbers. This function
 *   also assumes 'a' is always greater or equal than 'b'.
 *   The result bignum may overlap with input bignums.
 *
 * \param[out] r A pointer to a result bignumber.
 * \param[in] a A pointer to a bignumber to substract from.
 * \param[in] b A pointer to a bignumber to substract.
 *
 * \return BM_SUCCESS if substraction succeeded.
 */

static int bm_sub_nosign( bm_t *r, const bm_t *a, const bm_t *b ) {
    int n, m;
    uint64_t c;   /**< Used also as a carry */

    m = BM_MAX(a->size,b->size); 
	c = 0ULL;

	if (m >= r->maxs) {
		/* make sure stuff fits into the destination bignum */
		if ((n = bm_resize(r)) != BM_SUCCESS) {
			return n;
		}
	}
    for (n = 0; n < m; n++) {
		uint64_t A=0ULL, B=0ULL;

		if (n < a->maxs) {
			A = a->b[n];
		}
		if (n < b->maxs) {
			B = b->b[n];
		}

		c = A - B + c;
        r->b[n] = c;
        c >>= 32;
    }
	while (n > 1) {
		if (r->b[n-1] == 0) {
			/* check if the highest long word is zero, i.e. we can 
 			 * make the number "size" smaller.. this just ensures
			 * prettier output so that less leading zeroes are
			 * output when printing the bignum.
			 */
			n--;
		} else {
			break;
		}
    }

	r->size = n;
    return BM_SUCCESS;
}

/**
 * \brief Add two bignums and neglect the sign, just do the required
 *   binary arithmetic. The target bignum gets "reset" and adjusted to 
 *   a required size.
 *
 * \param r A pointer to the target bignum.
 * \param a A pointer to a bignum to add.
 * \param b A pointer to a bignum to add.
 * \return BM_SUCCESS if ok, error otherwise.
 */

static int bm_add_nosign( bm_t *r, const bm_t *a, const bm_t *b ) {
    int n, m;
    uint64_t c;   /**< Used also as a carry */

    m = BM_MAX(a->size,b->size); 
	c = 0ULL;
    
	if (m >= r->maxs) {
		/* make sure stuff fits into the destination bignum */
		if ((n = bm_resize(r)) != BM_SUCCESS) {
			return n;
		}
	}
    for (n = 0; n < m; n++) {
		uint64_t A=0ULL, B=0ULL;

		if (n < a->maxs) {
			A = a->b[n];
		}
		if (n < b->maxs) {
			B = b->b[n];
		}

		c = A + B + c;
        r->b[n] = c;
        c >>= 32;
    }
    if (c) {
		r->b[n++] = c;
	}

	r->size = n;
    return BM_SUCCESS;
}

/**
 * \brief compare two bignumers and neglect the sign.
 *
 * \param a A pointer to a bignumber.
 * \param b A pointer to a bignumber.
 *
 * \return 0 if equal, >0 if a > b, and <0 otherwise.
 */

static int bm_cmp_nosign( const bm_t *a, const bm_t *b ) {
    int n;

	if (a->size < b->size) {
		return -1;
	}
	if (a->size > b->size) {
		return 1;
	}

	/* both bignums are equal "size" in memory */

    for (n =a->size-1; n >= 0; n--) {
        if (a->b[n] > b->b[n]) {
            return 1;
        }
        if (a->b[n] < b->b[n]) {
            return -1;
        }
    }
        
    return 0;
}

/**
 * \brief compare two bignumers.
 *
 * \param a A pointer to a bignumber.
 * \param b A pointer to a bignumber.
 *
 * \return 0 if equal, >0 if a > b, and <0 otherwise.
 */

int bm_cmp( const bm_t *a, const bm_t *b ) {
    int m,n;

	if (a->sign != b->sign) {
		if (a->sign == BM_NEG) {
			return -1;
		} else {
			return 1;
		}
	}
	if (a->size < b->size) {
		return -1 * a->sign;
	}
	if (a->size > b->size) {
		return 1 * a->sign;
	}

	return a->sign * bm_cmp_nosign(a,b);
}


/**
 * \brief Add (signed) two bignumers. Note that the result bignum
 *   can be one of the input bignums.
 *
 * \param r A pointer to a result bignumber.
 * \param a A pointer to a bignumber to add.
 * \param b A pointer to a bignumber to add.
 *
 * \return 0 if addition succeeded.
 */

int bm_add( bm_t *r, const bm_t *a, const bm_t *b ) {
	int m,n;
	uint64_t c;

	/*
	 * 1) r = a + b
	 * 2) r = a + (-b)  -> r = a - b
	 * 3) r = (-a) + b  -> r = b - a
	 * 4) r = (-a) + (-b)
	 */

    if (a->sign != b->sign) {
		m = bm_cmp_nosign(a,b);

		if (a->sign == BM_POS) {
            /* case 2)..  */
			r->sign = m >= 0 ? BM_POS : BM_NEG;
			return bm_sub_nosign(r,a,b); 
        } else {
            /* case 3)..  */
			r->sign = m > 0 ? BM_NEG : BM_POS;
            return bm_sub_nosign(r,b,a);
        }
    }

    /* cases 1) and 4) */

	r->sign = a->sign;
	return bm_add_nosign(r,a,b);
}


/**
 * \brief Add an unsigned integer to a bignum.
 *
 * \param[inout] a A pointer to a destination bignum.
 * \param[in] v An unsigned integer to add.
 *
 * \return BM_SUCCESS if OK, error otherwise.
 */

int bm_add_ui( bm_t * a, uint32_t v ) {
    int m,n;
    uint64_t c = 0;
    uint64_t d = (uint64_t)v;

    for (n = 0; n < a->size; n++) {
        uint64_t A = a->b[n];
        c = A + d + c;
        a->b[n] = c;
        c >>= 32;
    }
    if (c > 0) {
        if (a->size == a->maxs) {
            if ((m = bm_resize(a)) != BM_SUCCESS) {
                return m;
            }
        }
        a->b[a->size++] = c;
    }

    return BM_SUCCESS;
}

/**
 * \brief Add a signed integer to a bignum. 
 *
 * \param[inout] a A pointer to a destination bignum.
 * \param[in] v A signed integer to add.
 *
 * \return BM_SUCCESS if OK, error otherwise.
 */

int bm_add_si( bm_t * a, int32_t v ) {
    int m,n;
    uint64_t c = 0;
    uint64_t d = (uint64_t)v;
	int sign = v >= 0 ? BM_POS : BM_NEG;

	/* The obly case where sign can change is when the size of the bignum is 1 */

	if (a->size == 1 && a->sign != sign) {
		a->sign *= sign;
	}
    for (n = 0; n < a->size; n++) {
        uint64_t A = a->b[n];
        c = A + d + c;
        a->b[n] = c;
        c >>= 32;
    }
    if (c > 0) {
		if (a->sign == BM_NEG && c != 0xffffffff) {
			if (a->size == a->maxs) {
				if ((m = bm_resize(a)) != BM_SUCCESS) {
					return m;
				}
			}
			a->b[a->size++] = c;
		}
    }

    return BM_SUCCESS;
}


/**
 * \brief Sub (signed) two bignumers. Note that the result 
 *   bignum may be one of the input bignums.
 *
 * \param r A pointer to a result bignumber.
 * \param a A pointer to a bignumber to add.
 * \param b A pointer to a bignumber to add.
 *
 * \return 0 if addition succeeded.
 */

int bm_sub( bm_t *r, const bm_t *a, const bm_t *b ) {
    int m,n;
	uint64_t c;

    /* test signess cases. There are four case:
     * 1) r = a - b       -> r = a - b
     * 2) r = a - (-b)    -> r = a + b
     * 3) r = (-a) - b    -> r = (-b) + (-a)
     * 4) r = (-a) - (-b) -> r = b - a
     */

    if (a->sign != b->sign) {
        /* case 2) and 3) */
		r->sign = a->sign;
        return bm_add_nosign(r,a,b);
    }

	/* cases 1) and 4) */

	if (bm_cmp_nosign(a,b) < 0) {
		/* a < b ..  */
		const bm_t *t = a;
		a = b;
		b = t;
		r->sign = a->sign == BM_POS ? BM_NEG : BM_POS;
	} else {
		/* a >= b */
		r->sign = a->sign == BM_POS ? BM_POS : BM_NEG;
	}
   
	return bm_sub_nosign(r,a,b);
}

/**
 * \brief Set a bignumber value from a signed integer.
 *
 * \param r A pointer to a bignumber structure.
 * \param l A value to set.
 *
 * \return BM_SUCCESS.
 */

int bm_set_si( bm_t *r, int32_t l ) {
    int n;

    if ((n = bm_set_size(r,1)) != BM_SUCCESS) {
        return n;
    }
    if (l >= 0) {
        r->b[0] = (uint32_t)l;
        r->sign = BM_POS;
    } else {
        r->b[0] = (uint32_t)(-l);
        r->sign = BM_NEG;
    }

    return BM_SUCCESS;
}

/**
 * \brief Set a bignumber value from an unsigned integer.
 *
 * \param r A pointer to a bignumber structure.
 * \param l A value to set.
 *
 * \return BM_SUCCESS.
 */

int bm_set_ui( bm_t *r, uint32_t l ) {
    int n;

    if ((n = bm_set_size(r,1)) != BM_SUCCESS) {
        return n;
    }
    
    r->sign = BM_POS;
    r->b[0] = l;
    return BM_SUCCESS;
}

/**
 * \brief Set a bignumber value from an array of octets. The bignum is
 *   implicitly set to positive value.
 *
 * \param r A pointer to a bignumber structure.
 * \param b A pointer to an octet array.
 * \param i The length of the array.
 *
 * \return BM_SUCCESS or an error.
 */

int bm_set_b( bm_t *r, const unsigned char *b, int i ) {
    int n,m;
	uint32_t l;

	if (i < 1) {
		return -BM_ERROR_NOT_A_NUMBER;
	}

	/* get the number of long words the number is going to take */
    m = get_size_in_longs(i);

    if (m > r->maxs) {
		if ((m = bm_resize(r)) != BM_SUCCESS) {
			return m;
		}
	}

	l = 0;
	m = 0;
	n = 0;

	while (i > 0) {
		l >>= 8;
		l |= b[--i] << 24;
		n++;

		if ((n & 3) == 0) {
			r->b[m++] = l;
			l = 0;
		}
	}
	if ((n & 3) != 0) { 
		l >>= (32 - (n & 3) * 8);
		r->b[m++] = l;
	}

	r->size = m;
    r->sign = BM_POS;
    return BM_SUCCESS;
}


/**
 * \brief Copies a bignum from another bignum.
 *
 * \param d A pointer to a destination bignum.
 * \param a A pointer to a source bignum.
 *
 * \return BM_SUCCESS if OK.
 */

int bm_set( bm_t *d, const bm_t *a ) {
	int n;
	
	if (a->maxs > d->maxs) {
	    if ((n = bm_set_size(d,a->maxs)) != BM_SUCCESS) {
            return n;
        }
	}

	d->size = a->size;
	d->sign = a->sign;

	for (n = 0; n < a->size; n++) {
		d->b[n] = a->b[n];
	}

	return BM_SUCCESS;
}

/**
 * \brief Get the sign of a bignum.
 *
 * \param a A pointer to a bignum.
 * \return BM_POS or BM_NEG.
 */

int bm_get_sign( const bm_t *a ) {
	assert(a->sign);
	return a->sign;
}

/**
 * \brief Change the signess of a bignum.
 *
 * \param a A pointer to a bignum.
 * \return BM_SUCCESS if ok.
 */

int bm_neg( bm_t *a ) {
	assert(a->sign);
	a->sign *= BM_NEG;
	return BM_SUCCESS;
}

/**
 * \brief Change the signess of an octet array.
 *
 * \param b A pointer to an octet array.
 * \param l The length of the octet array.
 * \return None.
 */

static void bm_neg_b( uint8_t *b, int l ) {
	int n;
	uint32_t c;

	assert(b);
	assert(l > 0);

	for (n = l-1, c = 0; n >= 0; n--) {
		uint32_t B = b[n];
		c = B + c + 0xff ^ 0xff;
		b[n] = c;
		c >>= 8;
	}
	
}

/**
 * \brief Get a bignumber value and store it into an octet array.
 *   If the number is negative, a NEG operation is firt applied
 *   to it.
 *
 * \param r A pointer to a bignumber structure.
 * \param b A pointer to an octet array.
 * \param i The length of the array.
 *
 * \return The length of output number in the octet array or an error.
 */

int bm_get_b( const bm_t *a, unsigned char *b, int i ) {
    int n,m;
	uint32_t l;
	uint8_t *b2 = b;

	if (i < 1) {
		return -BM_ERROR_INTERNAL_ERROR;
	}

	m = get_size_in_longs(i);

	if (m < a->size) {
		return -BM_ERROR_NUMBER_TOO_BIG;
	}
	
	/* the highest long word gets special treatment mostly
	 * to trim the output nicely i.e. no leading zeroes
	 */

	m = a->size;
	l = a->b[--m];

	if (l > 0x00ffffff) {
		n = 4;
	} else if (l > 0x0000ffff) {
		n = 3;
	} else if (l > 0x000000ff) {
		n = 2;
	} else if (l > 0x00000000) {
		n = 1;
	} else if (m > 0) {
		n = 0;
	} else {
		n = 1;
	}

	switch (n) {
	case 4:
		*b++ = l >> 24;
	case 3:
		*b++ = l >> 16;
	case 2:
		*b++ = l >> 8;
	case 1:
		*b++ = l;
	default:
		break;
	}
		
	while (--m >= 0) {
		l = a->b[m];
		*b++ = l >> 24;
		*b++ = l >> 16;
		*b++ = l >> 8;
		*b++ = l;
		n += 4;
	}

	/* check the sign */

	if (a->sign == BM_NEG) {
		bm_neg_b(b2,n);
	}

	return n;
}

/**
 * \brief A signed multiplication. This can be considered an elementary school
 *   level algorithm :) Note that the result bignum can be the same as either
 *   one of the input bignums. Also both input bignums can be the same. This is
 *   done at the expense of a temporary bignum, which takes some more space and
 *   slows down the function slightly.
 *
 * \param r A pointer to a result bignumber.
 * \param a A pointer to a bignumber to multiply.
 * \param b A pointer to a bignumber to multiplicant.
 *
 * \return BM_SUCCESS if multiplication succeeded. Note that
 *   if there is an error, the target bignun will be in inconsistent
 *   state, i.e. one cannot expect it to contain a valid number.
 */

int bm_mul( bm_t *r, const bm_t *a, const bm_t *b ) {
	int i,o,n,m;
	const bm_t *a1,*b1;
	bm_t rr;
    uint64_t c;

	/* make sure we got enough space for the result */

	m = a->size + b->size;

	/* check for pathetic cases */

	if (bm_is_zero(a) || bm_is_zero(b)) {
		return bm_set_si(r,0);
	}

    /* set the temp bignum.. */

    bm_init(&rr);

	/* we will have a non-zero result */

	rr.sign = a->sign * b->sign;

	while (m > rr.maxs) {
		if ((n = bm_resize(&rr)) != BM_SUCCESS) {
			return n;
		}
	}
	
	/* initialize the target bignum to all zeroes to ease the calculations */
	while (--m >= 0) {
		rr.b[m] = 0;
	}
	if (a->size >= b->size) {
		a1 = a; 
		b1 = b;
	} else {
		a1 = b;
		b1 = a;
	}
	for (o = 0; o < b1->size; o++) {
		uint64_t B=(uint64_t)b1->b[o];
		c = 0ULL;
		
		if (B == 0) {
			continue;
		}
		for (i = 0; i < a1->size; i++) {
			uint64_t A = a1->b[i];
			uint64_t R = rr.b[o+i];
			c = A * B + R + c;
			rr.b[o+i] = c;
			c >>= 32;
		}
		if (c) {
			rr.b[o+i] = c;
		}
	}

	bm_trim(&rr,o+i);
	o = bm_set(r,&rr);
    bm_done(&rr);

    return n;
}

/**
 * \brief Bitwise logical shift left.  Note that the result bignum
 *   can also be the input bignum.
 *
 * \param[out] r A pointer to a result bignum.
 * \param[in] a A pointer to a bignum to shift.
 * \param[in] n Number of bits to shift (0 to 31).
 * \return BM_SUCCESS if OK, error otherwise.
 */

int bm_asl( bm_t *r, const bm_t *a, int n ) {
	uint32_t c;
	int i;

	n %= 32;

	if (a->size >= r->maxs) {
		if ((i = bm_resize(r)) != BM_SUCCESS) {
			return i;
		}
	}
	for (i = 0, c = 0; i < a->size; i++) {
		uint32_t A = a->b[n];
		r->b[i] = A << n | c;
		c = A >> 32-n;
	}
	if (c) {
		r->b[i++] = c;
	}

	r->size = i;
	r->sign = a->sign;
	return BM_SUCCESS;
}

/**
 * \brief Bitwise arithmetic shift right. Note that the result bignum
 *   can be the input bignum.
 *
 * \param[out] r A pointer to a result bignum.
 * \param[in] a A pointer to a bignum to shift.
 * \param[in] n Number of bits to shift (0 to 31).
 * \return BM_SUCCESS if OK, error otherwise.
 */

int bm_asr( bm_t *r, const bm_t *a, int n ) {
	uint32_t c;
	int i;

	n %= 32;
    c = 0;

	for (i = a->size-1; i >= 0; i--) {
		uint32_t A = a->b[i];
		r->b[i]  = A >> n | c;
		c = A << 32-n;
	}

	bm_trim(r,a->size);
	r->sign = a->sign;
	return BM_SUCCESS;
}

/**
 * \brief A signed division. This can be considered an elementary school
 *   level algorithm, which takes a lousy O(n^2) time.
 *
 * \param[out] q A pointer to a quotient bignumber.
 * \param[out] r A pointer to s reminder bignumber.
 * \param[in] n A pointer to a bignumber to numerator.
 * \param[in] d A pointer to a bignumber to denominator.
 *
 * \return BM_SUCCESS if multiplication succeeded. Note that
 *   if there is an error, the target bignun will be in inconsistent
 *   state, i.e. one cannot expect it to contain a valid number.
 */

int bm_div( bm_t *q, bm_t *r, const bm_t *n, const bm_t *d ) {
	int i,o,m;
    bm_t t;

	/* check for pathetic cases */

	if (bm_is_zero(d)) {
		return BM_ERROR_DIV_BY_ZERO;
	}

    m = bm_cmp_nosign(n,d);

    if (m == 0) {
        if ((m = bm_set_si(r,0)) != BM_SUCCESS) {
            return m;
        }
        m = n->sign * d->sign;
        return bm_set_si(q,m);
    }
    if (m < 0) {
        if ((m = bm_set_si(q,0)) != BM_SUCCESS) {
            return m;
        }
        return bm_set(r,n);
    }

	/* we will probably have a non-zero result */

    m = n->size - d->size + 1;

	while (m > r->maxs) {
		if ((i = bm_resize(r)) != BM_SUCCESS) {
            return i;
		}
    }
    while (m > q->maxs) {
        if ((i = bm_resize(q)) != BM_SUCCESS) {
            return i;
        }
	}

    /* long divide algorithm.. not the greatest ;-) The algorithm is
	 * basically the normal school division algorithm shifting in 
	 * long words of numerator as needed.
	 *
     * Shift in denominator size of long words of nominator for division
	 */
	
    bm_set_si(q,0);
    i = n->size;
    
	/* this is special, we are hand crafting remainder bignum.. */
	r->size = 0;

    while (i > 0) {
        uint32_t c = 0;
      
		for (m = r->size; m > 0; m--) {
			r->b[m] = r->b[m-1];
		}
		r->b[0] = n->b[--i];
		r->size++;

		while ((m = bm_cmp_nosign(r,d)) >= 0) {
			c++;
			bm_sub_nosign(r,r,d);
		}
        if (c > 0) {
            if ((m = bm_add_ui(q,c)) != BM_SUCCESS) {
                return m;
            }
        }
    }

    /* and last fix the sign */

    r->sign = n->sign * d->sign;
    q->sign = r->sign;
	return BM_SUCCESS;
}


/**
 * \brief Calculate a modular exponentiation.
 * \param[out] r A pointer to a result bignum.
 * \param[in] b A pointer to a base bignum value.
 * \param[in] e A pointer to an exponent bignum value.
 * \param[in] m A pointer to a modulus bignum value.
 *
 * \return BM_SUCCESS if OK. Negative error code otherwise.
 *
 * The following algorithm is used for calculating the modular
 * exponentiation.
 *
 *
 * function modular_pow(base, exponent, modulus)
 *   result := 1
 *	while exponent > 0
 *		if (exponent mod 2 == 1):
 *		   result := (result * base) mod modulus
 *	   exponent := exponent >> 1
 *	   base = (base * base) mod modulus
 *   return result
 *
 */

int bm_powm( bm_t *r, const bm_t *b, const bm_t *e, const bm_t *m ) {
	int n,i;
	bm_t nil, exp, bas, tmp;

    bm_init(&nil); bm_init(&exp); bm_init(&bas); bm_init(&tmp);

    if ((n = bm_set_ui(r,1)) != BM_SUCCESS) {
        goto powm_err;
    }
    if ((n = bm_set(&bas,b)) != BM_SUCCESS) {
        goto powm_err;
    }
    if ((n = bm_set(&exp,e)) != BM_SUCCESS) {
        goto powm_err;
    }
    while (!bm_is_zero(&exp)) {
        if (exp.b[0] & 1) {
            bm_mul(r,r,&bas);
            bm_set(&tmp,r);
            bm_div(&nil,r,&tmp,m);
        }
        bm_asr(&exp,&exp,1);
        bm_mul(&bas,&bas,&bas);
        bm_set(&tmp,&bas);
        bm_div(&nil,&bas,&tmp,m);
    }

    n = BM_SUCCESS;
powm_err:
    bm_done(&nil); bm_done(&exp); bm_done(&bas); bm_done(&tmp);
	return n;
}


/**

*/


#if !defined(PARTOFLIBRARY)
static void output(char *title, const bm_t *r ) {
	uint8_t o[BM_MAX_SIZE];
	int n = bm_get_b(r,o,BM_MAX_SIZE);
	int m;

	printf("%s => ",title);

	if (n > 0) {
		if (r->sign == BM_NEG) {
			printf("minus ");
		}
		for (m = 0; m < n; m++) {
			printf("%02x",o[m]);
		}
	}
	printf("\n\n");
}



const uint8_t num1[] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
const uint8_t num2[] = {0xab,0xbc,0xde,0xf0,0x12,0x34};


int main( int argc, char **argv) {
	int n,m;

	bm_t r,a,b,c,d;
	bm_t nom,den,rem,quo;

	bm_init(&nom); bm_init(&den); bm_init(&rem); bm_init(&quo);

	bm_init(&r);
	bm_init(&a);
	bm_init(&b);
	bm_init(&c);
	bm_init(&d);

    bm_set_ui(&a,4);
    bm_set_ui(&b,13);
    bm_set_ui(&c,497);
    bm_powm(&r,&a,&b,&c);
    output("bm_powm() result: ",&r);




	bm_set_si(&nom,66778811);
	bm_set_si(&den,678);
	bm_div(&quo,&rem,&nom,&den);
	output("bm_div() quotient: ",&quo);
	output("bm_div() reminder: ",&rem);

	bm_set_b(&nom,num1,sizeof(num1));
	bm_set_b(&den,num2,sizeof(num2));
	bm_div(&quo,&rem,&nom,&den);
	output("bm_div() quotient: ",&quo);
	output("bm_div() reminder: ",&rem);

	//

	//bm_set_ui(&a,0xffffffff);
	//bm_set_ui(&b,0xffffffff);
	bm_set_b(&c,num1,sizeof(num1));
	bm_set_b(&d,num2,sizeof(num2));
	
	bm_set_si(&a,-6666);
	bm_set_si(&b,7777);
	
	bm_add(&r,&a,&b);
	output("bm_add(-6666,7777)",&r);
	
	bm_neg(&r);
	output("bm_neg()",&r);

	bm_add(&r,&b,&a);
	output("bm_add(7777,-6666)",&r);

	bm_add(&r,&a,&a);
	output("bm_add(-6666,-6666)",&r);

	bm_add(&r,&b,&b);
	output("bm_add(7777,7777)",&r);

	bm_sub(&r,&a,&b);
	output("bm_sub(-6666,7777)",&r);

	bm_sub(&r,&b,&a);
	output("bm_sub(7777,-6666)",&r);

	bm_sub(&r,&a,&a);
	output("bm_sub(-6666,-6666)",&r);

	bm_sub(&r,&b,&b);
	output("bm_sub(7777,7777)",&r);


	bm_mul(&r,&b,&b);
	output("**bm_mul()",&r);


	output("num1: ",&c);
	output("num2: ",&d);

	bm_mul(&r,&c,&d);
	output("**bm_mul()",&r);

	bm_done(&nom); bm_done(&den); bm_done(&rem); bm_done(&quo);

	bm_done(&r);
	bm_done(&a);
	bm_done(&b);
	bm_done(&c);
	bm_done(&d);

    return 0;
}


#endif
