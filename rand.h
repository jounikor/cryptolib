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

uint64_t rand_get64( void );
uint32_t rand_get32( void );


/* */

enum rand_kind {
	MT19937=0,
	MT19937_64,
	WELL44497a
};


#define MT32SIZE 624
#define MT64SIZE 312
#define MT64HALF 156

/* WELL4497a */

#define W 32
#define R 1391
#define DISCARD 15
#define MASKU (0xffffffffU>>(W-DISCARD))
#define MASKL (~MASKU)

#define M1 23
#define M2 481
#define M3 229

#define MAT0POS(t,v) (v^(v>>t))
#define MAT0NEG(t,v) (v^(v<<(-(t))))
#define MAT1(v) v
#define MAT2(a,v) ((v & 1U)?((v>>1)^a):(v>>1))
#define MAT3POS(t,v) (v>>t)
#define MAT3NEG(t,v) (v<<(-(t)))
#define MAT4POS(t,b,v) (v ^ ((v>>  t ) & b))
#define MAT4NEG(t,b,v) (v ^ ((v<<(-(t))) & b))
#define MAT5(r,a,ds,dt,v) ((v & dt)?((((v<<r)^(v>>(W-r)))&ds)^a):(((v<<r)^(v>>(W-r)))&ds))
#define MAT7(v) 0

#define V0            STATE[state_i]
#define VM1Over       STATE[state_i+M1-R]
#define VM1           STATE[state_i+M1]
#define VM2Over       STATE[state_i+M2-R]
#define VM2           STATE[state_i+M2]
#define VM3Over       STATE[state_i+M3-R]
#define VM3           STATE[state_i+M3]
#define Vrm1          STATE[state_i-1]
#define Vrm1Under     STATE[state_i+R-1]
#define Vrm2          STATE[state_i-2]
#define Vrm2Under     STATE[state_i+R-2]

#define newV0         STATE[state_i-1]
#define newV0Under    STATE[state_i-1+R]
#define newV1         STATE[state_i]
#define newVRm1       STATE[state_i-2]
#define newVRm1Under  STATE[state_i-2+R]

/*output transformation parameter*/
#define newVM2Over    STATE[state_i+M2-R+1]
#define newVM2        STATE[state_i+M2+1]
#define BITMASK 0x48000000





#endif /* _rand_h_included */
