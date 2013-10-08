/**
 * \file uuid.c
 * \brief The RFC4122 implementation of the UUID.
 * \author Jouni Korhonen
 * \email jouni.korhonen@iki.fi
 * \date 2013-10-4
 * \version 0.1 (initial)
 * \copyright Not GPL
 *
 *
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "uuid.h"
#include "sha1.h"
#include "synchronization.h"
#include "rand.h"


/* Name string is a fully-qualified domain name */
static const uuid_t NameSpace_DNS = { /* 6ba7b810-9dad-11d1-80b4-00c04fd430c8 */
	0x6ba7b810,
	0x9dad,
	0x11d1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
};

/* Name string is a URL */
static const uuid_t NameSpace_URL = { /* 6ba7b811-9dad-11d1-80b4-00c04fd430c8 */
	0x6ba7b811,
	0x9dad,
	0x11d1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
};

/* Name string is an ISO OID */
static const uuid_t NameSpace_OID = { /* 6ba7b812-9dad-11d1-80b4-00c04fd430c8 */
	0x6ba7b812,
	0x9dad,
	0x11d1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
};

/* Name string is an X.500 DN (in DER or a text output format) */
static const uuid_t NameSpace_X500 = { /* 6ba7b814-9dad-11d1-80b4-00c04fd430c8 */
	0x6ba7b814,
	0x9dad,
	0x11d1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
};



/**
 * \brief Test endianess whether we are using little endian.
 * \return 0 if big endian, not 0 if little endian.
 *
 */

static int host_is_little_endian( void ) {
    uint16_t e = 0x55aa;

    if ((&e)[0] == 0x55) {
        return 0;
    } else {
        return 1;
    }
}

static uint16_t swap16u( uint16_t v ) {
    return v >> 8 | v << 8;
}

static uint32_t swap32u( uint32_t v ) {
    uint16_t w = v >> 8;
    return v >> 24 | v << 24 | swap16u(w) << 8; 
}

static void swap_endianess( uuid_t *u ) {
    /* The UUID is by default in the network byte order, so
     * changing the endianess is only needed when the host
     * is a little endian one.
     */
    if (!host_is_little_endian()) {
        return;
    }

    u->uuid.time_low = swap32u(u->uuid.time_low);
    u->uuid.time_mid = swap16u(u->uuid.time_mid);
    u->uuid.time_hi_ver = swap16u(u->uuid.time_hi_ver);
}

static uint16_t clock_seq;


/**
 * \brief Initialized teh clock sequence numbering to be used with the UUID
 *   Version 1 Variant '0b10x'.
 * \param[in] seed A seed for the "bad random number" generator.
 * \returb Nothing.
 */

void uuid_seq_init( int seed ) {
	/* This is something bad.. */
	clock_seq = 0xcafe;
}

/**
 * \brief Get the current clock sequence and increase the internal
 *   clock sequence counter.
 * \return The current clock sequence value.
 *
 */

uint16_t uuid_get_seq( void ) {
	uint16_t t = clock_seq;
	ATOMIC_OPERATION(++clock_seq);
	return t;
}

/**
 * \brief UUID version 2 of variation '0b10x' (DCE Security). This version
 *   of UUID is not supported.
 * \param[out] u A pointer to UUID to store the output.
 * \param[in] uid The UID.
 * \param[in] gid The GID.
 * \param[in] tv A pointer to uuid_timeval.
 * \return UUID_SUCCESS if OK, otherwise a negative error code. 
 */

int uuid_create_v2(uuid_t *u, int32_t uid, int32_t gid, const struct uuid_timeval *tv  ) {
    return UUID_ERROR_NOT_SUPPORTED_VERSION;
}

/**
 * \brief Insert either version 3 or 5 hash information into 
 *   the UUID.
 * \param[out] u A pointer to the UUID.
 * \param[in] h A pointer to the hash value.
 * \param[in] v Version to put into the UUID.
 * \return Nothing.
 */

static void fill_v3v5( uuid_t *u, const void *h, int v ) {
    uint8_t *uu, x;
    uint16_t w;
    memcpy(u,h,sizeof(uuid_t));
    
    /* fix version and variant */
    uu = (uint8_t *)u;
    x = uu[UUID_VERSION_INDEX];
    x = x & 0x0f | (v & 0x0f) << 4;
    uu[UUID_VERSION_INDEX] = x;

    x = uu[UUID_VARIANT_INDEX];
    x = x & 0x3f | 0x80;    /* only variany '0b10x' supported */
    uu[UUID_VARIANT_INDEX] = x;
}

/**
 * \brief UUID version 1 of variation '0b10x' (MAC address).
 * \param[out] u A pointer to a UUID to construct.
 * \param[in] tv A pointer to a timeval (time since January 1, 1970).
 * \param[in] mac A pointer to a MAC address (48 bits).
 * \return UUID_SUCCESS if ok. Negative error code if something failed.
 */

int uuid_create_v1( uuid_t *u, const struct uuid_timeval *tv, const uint8_t *mac ) {
    uint64_t t;
	uint16_t s = uuid_get_seq();

    /* UUID base time is 100-nanosecond intervals since the adoption
     * of the Gregorian calendar in the West, i.e. October 15, 1582.
     * Convert that to the UNIX base time, i.e. January 1, 1970.
     */

    t = (uint64_t)(10 * tv->tv_usec);       /* 1 usec = 10 * 100 nanosec */
    t += (uint64_t)(10000000 * tv->tv_sec); /* 1 sec = 10^7 * 100 nanosec */
    t += 0x01B21DD213814000ULL;             /* 100 nanosecs since October 15, 1582 */

    /* The MAC address is assumed to be 48 bits */
    memcpy(u->uuid.node,mac,6);

    /* fix version and variant */
    
	u->uuid.time_low = t;       /* Implicitly take the lowest 32 bits */
    u->uuid.time_mid = t >> 32; /* Implicitly take the mid 16 bits */
    u->uuid.time_hi_ver = t >> 48 & 0x0fff | 0x1000;    /* version 1 UUID */
    u->uuid.clock_seq_hi_var = s >> 8 & 0x3f | 0x80;	/* variant '0b10x' */
    u->uuid.clock_seq_lo = s;

    return UUID_SUCCESS;
}



/**
 * \brief UUID version 3 of variation '0b10x' (MD5 hash). This version
 *   of the UUID is not supported.
 * \param[out] u A pointer to UUID to store the output.
 * \param[in] n A pointer to a buffer holding an URL.
 * \param[in] l The length of the buffer.
 * \return UUID_SUCCESS if OK, otherwise a negative error code. 
 */

int uuid_create_v3(uuid_t *u, const void *n, int l ) {
    /* We do not support MD5, that's the reason.. */
    return UUID_ERROR_NOT_SUPPORTED_VERSION;
}

/**
 * \brief Create a UUID cversion 4 variation '0b10x' (Random).
 * 
 *
 *
 */

int uuid_create_v4( uuid_t *u, uint32_t seed ) {
	uint32_t *rnd;

	if (seed) {
		rand_init(MT19937,seed);
	}

	rnd = (uint32_t *)&u->uuid_a[0];
	rnd[0] = rand_get32();
	rnd[1] = rand_get32();
	rnd[2] = rand_get32();
	rnd[3] = rand_get32();
	rnd[3] = 0;
    u->uuid.time_hi_ver = u->uuid.time_hi_ver & 0x0fff | 0x4000;    /* version 4 UUID */
    u->uuid.clock_seq_hi_var = u->uuid.clock_seq_hi_var & 0x3f | 0x80;	/* variant '0b10x' */
	return UUID_SUCCESS;
}



/**
 * \brief UUID version 5 of variation '0b10x' (SHA-1 hash).
 * \param[out] u A pointer to UUID to store the output.
 * \param[in] n A pointer to a buffer holding an URL.
 * \param[in] l The length of the buffer.
 * \return UUID_SUCCESS if OK, otherwise a negative error code. 
 */

int uuid_create_v5(uuid_t *u, const void *n, int l ) {
    uint8_t hsh[SHA1_HSH_SIZE];
    sha1_context stx;
    crypto_context *ctx;

    ctx = sha1_init(&stx); 
    ctx->reset(ctx);
    ctx->update(ctx,n,l);
    ctx->finish(ctx,hsh);
    ctx->free(ctx);
    
    /* Use only 128 first bits out of the SHA-1 hash and versio 5*/
   
    fill_v3v5( u, hsh, 5 );

    /* Shuffle the structure into host byte order.. We should use proper
     * libraries or project wide defines for this purpose but we are
     * not.. lame..
     */
    
    swap_endianess( u );
    
    return UUID_SUCCESS;
}

/**
 * \brief Serialize an UUID structure i.e. transfer it into
 *   a network byte ordered buffer..
 * \param[out] o A pointer to an output buffer. The buffer must
 *   have enough space to hold the UUID.
 * \param[in] u A pointer to the UUID to serialize.
 * \return Nothing.
 *
 */

void uuid_serialize( void *o, const uuid_t *u ) {
    memcpy(o,u,sizeof(uuid_t));
    swap_endianess( (uuid_t *)o );
}

/** 
 * \brief Unpack a octet buffer into an UUID structure. 
 * \param[out] u A pointer to the output UUID.
 * \param[in] i A pointer to a serialized octet buffer
 *   containing an UUID.
 * \return Nothing.
 *
 */

void uuid_unpack( uuid_t *u, const void *i ) {
    memcpy(u,i,sizeof(uuid_t));
    swap_endianess( u );
}

/**
 * \brief Extract the version information out of the UUID structure.
 * \param[in] u A pointer to an UUID structure.
 * \return Extracted UUID version.
 *
 */

int uuid_get_version( const uuid_t *u ) {
    return (int)(u->uuid.time_hi_ver >> 12);
}

/**
 * \brief Extract the variant information out of the UUID structure.
 * \param[in] u A pointer to an UUID structure.
 * \return Extracted UUID variant.
 *
 */

int uuid_get_variant( const uuid_t *u ) {
    return (int)(u->uuid.clock_seq_hi_var >> 5);
}

/**
 * \brief Extract the version information out of the UUID buffer.
 * \param[in] u A pointer to an UUID buffer. The UUID in the
 *   buffer must be in a serialized form.
 * \return Extracted UUID version.
 *
 */

int uuid_get_version_b( const void *u ) {
    uuid_t *uu = (uuid_t *)u;
    return (int)(uu->uuid_a[UUID_VERSION_INDEX] & 0xf0) >> 4;
}

/**
 * \brief Extract the variant information out of the UUID buffer.
 * \param[in] u A pointer to an UUID buffer. The UUID in the
 *   buffer must be in a serialized form.
 * \return Extracted UUID variant.
 *
 */

int uuid_get_variant_b( const void *u ) {
    uuid_t *uu = (uuid_t *)u;
    return (int)(uu->uuid_a[UUID_VARIANT_INDEX] & 0xf0) >> 4;
}

/**
 * \brief Test if the UUID is empty..
 * \param[in] u A pointer to an UUID structure.
 * \return 0 if not empty, non-zero if empty.
 *
 */

int uuid_is_zero( const uuid_t *u ) {
    int n = sizeof(uuid_t);

    while (n-- > 0) {
        if (u->uuid_a[n] != 0) {
            return 0;
        }
    }

    return 1;
}


//#if !defined(PARTOFLIBRARY)

void print_uuid( const uuid_t *u ) {
	int n,m;

	uint8_t b[16];
	uuid_serialize(b,u);

	printf("UUID version %d, variant %#x\n\t ",
		(b[UUID_VERSION_INDEX] & 0xf0) >> 4,
		(b[UUID_VARIANT_INDEX] & 0xe0) >> 5);
	for (n = 0; n < 4; n++) {
		printf("%02x",b[n]);
	}
	printf("-");
	for (n = 0; n < 2; n++) {
		printf("%02x",b[4+n]);
	}
	printf("-");
	for (n = 0; n < 2; n++) {
		printf("%02x",b[6+n]);
	}
	printf("-");
	for (n = 0; n < 2; n++) {
		printf("%02x",b[8+n]);
	}
	printf("-");
	for (n = 0; n < 6; n++) {
		printf("%02x",b[12+n]);
	}
	printf("\n");
}



int main( int argc, char **argv ) {

	uuid_t u1;
	uuid_t u2 = NameSpace_X500;

	print_uuid(&u2);



	printf("%08x=%08x ja %04x=%04x\n",
		0x11223344,swap32u(0x11223344),0xabcd,swap16u(0xabcd));


	uuid_create_v4(&u1,0xabadcafe);
	print_uuid(&u1);



    return 0;
}


//#endif

