/**
 * \file asn1_parser.c
 * \brief A minimalistinc ASN1 (DER) encoder.
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
 * \param[in] ctx A pointer to the asn1_parser structure.
 * \return Length or an error (a negative number).
 */

static int asn1_parse_len( asn1_parser_t *ctx ) {
    uint8_t c;
    int n, m;
    
    if (ctx->asn1_type != asn1_der) {
        return -ASN1_ERROR_TYPE;
    }
    if (ctx->msg[ctx->ptr] == 0x80) {
        /* infinite form is not supported */
        return -ASN1_ERROR_INFINITE_FORM;
    }
    if ((c = ctx->msg[ctx->ptr++]) < 0x80) {
        /* length between 0 and 127 */
        return (int)c;
    }
    if (c == 0xff) {
        /* 1 1111111 not allowed as a length encoding */
        return -ASN1_ERROR_INVALID_ENCODING;
    }
    
    m = (int)(c & 0x7f);
    n = 0;

    if (m > 4) {
        /* this implementation only supports lengths up to 2^32 */
        return -ASN1_ERROR_TOO_LONG;
    }
    while (m-- > 0) {
        n <<= 8;
        n |= ctx->msg[ctx->ptr++];
    }

    return n;
}



/**
 * \brief Parse ASN1 tag value.
 * \param[in] ctx A pointer to the asn1_parser structure.
 * \return A tag value (without len, and other bits) or
 *   error (a nagetive number).
 */

static int asn1_parse_tag( asn1_parser_t *ctx ) {
    int tag;


    tag = 0;

    return tag;
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


