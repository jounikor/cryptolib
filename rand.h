#ifndef _rand_h_included
#define _rand_h_included

/**
 * \file rand.h
 * \brief Sample PRNG implementations. These are not cryptographically
 *   safe (CSPRNG) random numbers. Rather optimized for speed and size.
 *   Two Mersenne Twister algorithm variants are implemented:
 *     MT19937 for 32 bit random output
 *     MT19937-64 for 64 bit random outout.
 *   Both algorithms have the same memory requirement, i.e. ~2500 octets.
 *
 * \version 0.1 (initial)
 * \author Jouni Korhone (re-implementations of existing algortihms)
 * \email jouni.korhonen@iki.fi
 * \copyrigth I have no IDEA.
 *
 * Both algorithms (c) M. Matsumoto and T. Nishimura.
 *
 *  References:
 *   T. Nishimura, ``Tables of 64-bit Mersenne Twisters''
 *   ACM Transactions on Modeling and 
 *   Computer Simulation 10. (2000) 348--357.
 *   M. Matsumoto and T. Nishimura,
 *   ``Mersenne Twister: a 623-dimensionally equidistributed
 *   uniform pseudorandom number generator''
 *   ACM Transactions on Modeling and 
 *   Computer Simulation 8. (Jan. 1998) 3--30.
 */


#include <stdint.h>
#include <stdarg.h>

int rand_init( int, ... );

uint64_t rand_get( void );

/* */

enum rand_kind {
	MT19937=0,
	MT19937_64
};


#define MT32SIZE 624
#define MT64SIZE 312
#define MT64HALF 156



#endif /* _rand_h_included */
