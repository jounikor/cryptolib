#ifndef _uuid_h_included
#define _uuid_h_included

/**
 * \file uuid.h
 * \brief A header file for RFC4122 UUID handling. The implementation supports
 *   only the variant "10x".
 * \author Jouni Korhonen
 * \email jouni.korhonen@iki.fi
 * \version 0.1 (initial)
 * \date 2013-9-30
 * \copyright Not GPL
 *
 *
 */


#include <stdint.h>

/* From wiki

   In the canonical representation, xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx, the
   most significant bits of N indicates the variant (depending on the variant;
   one, two, or three bits are used). The variant covered by the UUID
   specification is indicated by the two most significant bits of N being 1 0
   (i.e., the hexadecimal N will always be 8, 9, A, or B).

   The variant covered by the UUID specification has five versions. For this
   variant, the four bits of M indicates the UUID version (i.e., the
   hexadecimal M will be either 1, 2, 3, 4, or 5).

*/

struct uuid_timeval {
    int32_t tv_sec;     /**< seconds since Jan. 1, 1970 */
    int32_t tv_usec;    /**< and microseconds */
};

enum UUID_version_e {
	UUID_version_1 = 1,
	UUID_version_2,
	UUID_version_3,
	UUID_version_4,
	UUID_version_5
};

typedef union uuid_u {
    struct uuid_s {
        uint32_t time_low;
	    uint16_t time_mid;
	    union {
            uint16_t time_hi;
            uint8_t version;
        } M;
	    union {
            uint8_t clock_seq_hi;
            uint8_t variant;
        } N;
	    uint8_t clock_seq_low;
	    uint8_t node[6];
    } uuid;
    uint8_t uuid_a[16];
} uuid_t;



#define UUID_VERSION_MASK 0xf0
#define UUID_VARIANT_MASK 0xc0  /**< Only "10x" variant type supported. */
#define UUID_VARIANT_INDEX 8
#define UUID_VERSION_INDEX 6



int uuid_get_version_b( const void * );
int uuid_get_variant_b( const void * );
int uuid_get_version( const uuid_t * );
int uuid_get_variant( const uuid_t * );
int uuid_is_zero( const uuid_t * );
void uuid_serialize( void *, const uuid_t * );
void uuid_unpack( uuid_t *, const void * );

int uuid_create_v1( uuid_t *, const struct uuid_timeval *, const uint8_t * );
int uuid_create_v2( uuid_t *, int32_t, int32_t, const struct uuid_timeval *  );
int uuid_create_v3( uuid_t *, const void *, int );  /* URL based */
int uuid_create_v4( uuid_t *, long );    /* random number based */
int uuid_create_v5( uuid_t *, const void *, int );  /* 





/**
 * \brief Error codes for UUID handling.
 *
 *
 */

#define UUID_SUCCESS    0
#define UUID_ERROR_NOT_SUPPORTED_VARIANT    1
#define UUID_ERROR_NOT_SUPPORTED_VERSION    2
#define UUID_ERROR_NO_MEMORY                3





#endif /* _uuid_h_included */
