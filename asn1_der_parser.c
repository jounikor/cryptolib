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


