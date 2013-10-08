/**
 * \file rand.c
 * \brief Simple (reprogrammed) implemementations of MT19937 and
 *   MT19937-64 algorithms. The implementation is thread safe.. supposedly.
 * \version 0.1 (initial)
 * \date 2013-10-07
 * \author Jouni Korhonen
 * \email jouni.korhonen@iki.fi
 * \copyrithm I have no IDEA.
 *
 */


#include <stdio.h>

#include "rand.h"
#include "synchronization.h"

static union {
	uint32_t mt32[MT32SIZE];
	uint64_t mt64[MT64SIZE];
} mt;

static int index;

/*
 *
 *
 *
 *
 */

static void init_MT19937( uint32_t seed ) {
	int n;
	
	mt.mt32[0] = seed;
	index = 0;

	for (n = 1; n < MT32SIZE; n++) {
		mt.mt32[n] = 0x6c078965 * (mt.mt32[n-1] ^ (mt.mt32[n-1] >> 30)) + n;
	}
}

static uint32_t impl_MT19937( void ) {
	uint32_t y;

	ENTER_CRITICAL_SECTION;

	if (index == 0) {
		int n;
		
		for (n = 0; n < MT32SIZE; n++) {
			y = (mt.mt32[n] & 0x80000000)						/* bit 31 (32nd bit) of mt[n] */
			  + (mt.mt32[(n+1) % MT32SIZE] & 0x7fffffff);		/* bits 0-30 (first 31 bits) of mt[...] */
			mt.mt32[n] = mt.mt32[(n + 397) % MT32SIZE] ^ (y >> 1);
		
			if (y & 1) { // y is odd
				mt.mt32[n] = mt.mt32[n] ^ 0x9908b0df;
			}
		}
	}
						    
	y = mt.mt32[index++];
	y ^= (y >> 11);
	y ^= ((y << 7) & 0x9d2c5680);
	y ^= ((y << 15) & 0xefc60000);
	y ^= (y >> 18);

	index %= MT32SIZE;

	LEAVE_CRITICAL_SECTION;
	return y;
}


static int index64;
static int algo;

static void init_genrand64( uint64_t seed ) {
	mt.mt64[0] = seed;
	
	for (index64 = 1; index64 < MT64SIZE; index64++) {
		mt.mt64[index64]	= (6364136223846793005ULL * (mt.mt64[index64-1]
							^ (mt.mt64[index64-1] >> 62)) + index64);
	}
}

static void init_MT19937_64( uint64_t *mt64keys, uint64_t key_length ) {
	index64 = MT64SIZE+1;
	uint64_t i, j, k;

	init_genrand64(19650218ULL);

	i = 1;
	j = 0;
	k = (MT64SIZE > key_length ? MT64SIZE : key_length);

	for (; k; k--) {
		mt.mt64[i]	= (mt.mt64[i] ^ ((mt.mt64[i-1] 
					^ (mt.mt64[i-1] >> 62)) * 3935559000370003845ULL))
					+ mt64keys[j] + j; /* non linear */
		i++;
		j++;
  
		if (i >= MT64SIZE) {
				mt.mt64[0] = mt.mt64[MT64SIZE-1];
				i=1;
		}
		if (j >= key_length) {
			j = 0;
		}
	}
	for (k = MT64SIZE-1; k; k--) {
		mt.mt64[i] = (mt.mt64[i] ^ ((mt.mt64[i-1] ^ (mt.mt64[i-1] >> 62)) *
		  2862933555777941757ULL)) - i; /* non linear */
		i++;
	
		if (i >= MT64SIZE) {
			mt.mt64[0] = mt.mt64[MT64SIZE-1];
			i=1;
		}
	}

	mt.mt64[0] = 1ULL << 63; /* MSB is 1; assuring non-zero initial array */ 
}

static const uint64_t m[] = {0ull, 0xB5026F5AA96619E9ULL};

static uint64_t impl_MT19937_64( void ) {
	int i;
	uint64_t x;
	
	ENTER_CRITICAL_SECTION;

	if (index64 >= MT64SIZE) { /* generate NN words at one time */
		/* if init_genrand64() has not been called, */
		/* a default initial seed is used     */
		if (index64 == MT64SIZE+1) { 
			init_genrand64(5489ULL); 
		}
		for (i = 0; i < MT64SIZE-MT64HALF; i++) {
			x = (mt.mt64[i] & 0xFFFFFFFF80000000ULL)|(mt.mt64[i+1] & 0x7FFFFFFFULL);
			mt.mt64[i]	= mt.mt64[i + MT64HALF] ^ (x >> 1) ^ m[(x & 1ULL)];
		}
		for (; i < MT64SIZE-1; i++) {
			x = (mt.mt64[i] & 0xFFFFFFFF80000000ULL)|(mt.mt64[i+1] & 0x7FFFFFFFULL);
			mt.mt64[i] = mt.mt64[i + (MT64SIZE-MT64HALF)] ^ (x >> 1) ^ m[(x & 1ULL)];
		}

		x = (mt.mt64[MT64SIZE-1] & 0xFFFFFFFF80000000ULL)|(mt.mt64[0] & 0x7FFFFFFFULL);
		mt.mt64[MT64SIZE-1] = mt.mt64[MT64HALF-1] ^ (x >> 1) ^ m[(x & 1ULL)];

		index64 = 0;
	}

	x = mt.mt64[index64++];
	x ^= (x >> 29) & 0x5555555555555555ULL;
	x ^= (x << 17) & 0x71D67FFFEDA60000ULL;
	x ^= (x << 37) & 0xFFF7EEE000000000ULL;
	x ^= (x >> 43);

	LEAVE_CRITICAL_SECTION;
	return x;
}



/**
 * \brief Initialize the state of the generator MT19937 or MT19937-64 PRNG.
 * \param[in] kind The algorithm to use.
 * \param[in] ... Variadic arguments depending on the algorithm kind.
 *                MT19937 takes an unsigned 32 bit seed.
 *                MT19937_64 takes no arguments.
 * \return 0 if everything is OK, -1 if unknown algorithm kind was proposed.
 */

int rand_init( int kind, ... ) {
	int n;
	uint32_t seed;
	va_list va;
	uint64_t *list;
	uint64_t size;

	switch (kind) {
	case MT19937:
		va_start(va,kind);
		seed = va_arg(va,uint32_t);
		va_end(va);
		init_MT19937( seed );
		break;
	case MT19937_64:
		va_start(va,kind);
		list = va_arg(va,uint64_t *);
		size = va_arg(va,uint64_t);
		va_end(va);
		init_MT19937_64(list,size);
		break;
	default:
		return -1;
	}

	algo = kind;
	return 0;
}

/**
 * \brief Get a random number.. up to 64 bits..
 *
 *
 *
 */

uint64_t rand_get64( void ) {
	return impl_MT19937_64();
}

/**
 * \brief Get a random number.. up to 32 bits..
 *
 *
 *
 */

uint32_t rand_get32( void ) {
	return impl_MT19937();
}






#if !defined(PARTOFLIBRARY)

static const uint64_t mt64keys[] = {0x12345ULL, 0x23456ULL, 0x34567ULL, 0x45678ULL};


int main( int argc, char **argv ) {
	int n;

	//rand_init(MT19937,0xabadcafe);
	rand_init(MT19937_64,mt64keys,4);

	for (n = 0; n < 100/4; n++) {
		printf("%16llx %16llx %16llx %16llx\n",
			rand_get64(),rand_get64(),rand_get64(),rand_get64());
	}

	return 0;
}
#endif



