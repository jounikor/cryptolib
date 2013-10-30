/**
 * \file asn1_parser.c
 * \brief A minimalistinc ASN1 (DER) encoder.
 *
 *    This parser has few additional constraints compared to a
 *    "proper" DER parser. First, TAG lengths are limited to
 *    28 bits. Second, Value length is limited to 32 bits. However,
 *    these should be enough for most uses.
 *
 * \author Jouni Korhonen
 * \email jouni.korhonen@iki.fi
 * \version 0.1 (initial)
 * \date 2013-10-23
 * \copyright Not GPL.
 *
 *
 */

#include <string.h>
#include <stdio.h>

#include "asn1_parser.h"

/**
 * \brief Parse the length.. although this parser is only for DER,
 *   the length parser does all long format and constructed.
 *
 * \param[in] ctx A pointer to the asn1_parser structure.
 * \return Length or an error (a negative number).
 */

static int asn1_parse_len( asn1_parser_t *ctx ) {
    uint8_t c;
    int n, m;
	int i = ctx->ptr;
    
    if (ctx->asn1_type != asn1_der) {
        return -ASN1_ERROR_TYPE;
    }
    if (ctx->msg[i] == 0x80) {
        /* infinite form is not supported by ASN.1 DER */
        ctx->ptr = i;
        ctx->infinite = 1;
        return -ASN1_ERROR_INFINITE_FORM;
    }
    if ((c = ctx->msg[i]) < 0x80) {
        /* length between 0 and 127 */
        ctx->ptr = i;
		return (int)c;
    }
    if (c == 0xff) {
        /* 1 1111111 not allowed as a length encoding */
        return -ASN1_ERROR_INVALID_MESSAGE;
    }
    
    m = (int)(c & 0x7f);
    n = 0;
	i++;

    if (m > 4) {
        /* this implementation only supports lengths up to 2^32 */
        return -ASN1_ERROR_TOO_LONG;
    }
    while (m-- > 0) {
        n <<= 8;
        n |= ctx->msg[i++];
    }

	ctx->ptr = i;
    return n;
}



/**
 * \brief Parse ASN1 tag value. This function does not advance the
 *   message data pointer.
 *
 * \param[in] ctx A pointer to the asn1_parser structure.
 * \return A tag value (without len, and other bits) or
 *   error (a nagetive number).
 */

static int asn1_parse_tag( asn1_parser_t *ctx ) {
	int tag;
    int i,c;

    /* Check for end-of-content mark if infinite length 
     * encoding is in use. Note that ASN.1 DER is not
     * supposed to support infinite length encoding.
     */

    if (ctx->infinite) {
        if (ctx->length - ctx->ptr < 2) {
            /* Message too short */
            return -ASN1_ERROR_INVALID_MESSAGE;
        }
        if (ctx->msg[ctx->ptr] == 0 && ctx->msg[ctx->ptr+1] == 0) {
            ctx->ptr += 2;
            ctx->infinite = 0;
            return ASN1_SUCCESS;
        }
    }
    
    tag = (int)ctx->msg[ctx->ptr++];
    ctx->class = tag & 0xc0;
    ctx->constructed = tag & 0x20;

    if (tag & 0x1f < 31) {
        /* One ectet tag.. */
        return tag & 0x1f;
    }

    /* long format tag.. >= 31 */

    tag = 0;
    i = 0;

    do {
        if (ctx->ptr >= ctx->length) {
            return -ASN1_ERROR_INVALID_MESSAGE;
        }
        if (i >= 4) {
            /* maximum 28 bits tag supported by this implementation */
            return -ASN1_ERROR_INVALID_TAG;
        }
        
        c = (int)ctx->msg[ctx->ptr++];
        tag <<= 7;
        tag |= c & 0x7f;
        i++;
    } while (c & 0x80);
	
    return tag;
}

/**
 * \brief Parse a number of primitives supported by DER.
 *
 *
 *
 */

 static int asn1_parse_boolean( asn1_context_t *ctx, int *res ) {
    if (ctx->msg[ctx->ptr++] == 0) {
        *res = 0;
    } else {
        *res = 1;
    }
    return ASN1_SUCCESS;
 }

static int asn1_parse_integer( asn1_context_t *ctx, int n, int *res ) {
    int m;
    int r;

    if (n < 1 || n > 5) {
        /* integer must be 1 to 5 octets */
        return -ASN1_ERROR_INVALID_VALUE;
    }
    for (m = 0, r = 0; m < n; m++) {
        r <<= 8;
        r |= ctx->msg[ctx->ptr++];
    }

    *res = r;
    return ASN1_SUCCESS;
}


/*

The most significant DER encoding constraints are:
o Length encoding must use the definite form
o Additionally, the shortest possible length encoding must be used
o Bitstring, octetstring, and restricted character strings must use the primitive encoding
o Elements of a Set are encoded in sorted order, based on their tag value
DER is widely used for digital certificates such as X.509.

*/



#if !defined(PARTOFLIBRARY)

int main( int argc, char **argv ) {


	return 0;
}


#endif


