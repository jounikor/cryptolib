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
    u->uuid.M.time_hi = swap16u(u->uuid.M.time_hi);
}


/**
 * \brief UUID version 2 of variation 10..
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
    x = x & 0x0f | v << 4;
    uu[UUID_VERSION_INDEX] = x;

    x = uu[UUID_VARIANT_INDEX];
    x = x & 0x3f | 0x80;    /* only variany '10x' supported */
    uu[UUID_VARIANT_INDEX] = x;


}



/**
 * \brief UUID version 3 of variation 10..
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
 * \brief UUID version 5 of variation 10..
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
    
    /* Use only 128 first bits out of the SHA-1 hash */
   
    fill_v3v5( u, hsh, sizeof(uuid_t) );

    /* Shuffle the structure into host byte order.. We should use proper
     * libraries of project wide defines for this purpose but we are
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
    return (int)(u->uuid.M.version & 0xf0) >> 4;
}

/**
 * \brief Extract the variant information out of the UUID structure.
 * \param[in] u A pointer to an UUID structure.
 * \return Extracted UUID variant.
 *
 */

int uuid_get_variant( const uuid_t *u ) {
    return (int)(u->uuid.N.variant & 0xf0) >> 4;
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
}



int main( int argc, char **argv ) {



    return 0;
}


//#endif

