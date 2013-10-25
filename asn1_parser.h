#ifndef _asn1_parser_h_included
#define _asn1_parser_h_included

/**
 * \file asn1_parser.h
 * \brief Prototypes and defines for the ASN1 (DER) parser.
 * \author Jouni Korhonen
 * \email jouni.korhonen@iki.fi
 
 *
 *
 */

enum asn1_class {
	ASN1_EOC = 0,
	ASN1_BOOLEAN,
	ASN1_INTEGER,
	ASN1_BITSTRING,
	ASN1_OCTETSTRING,
	ASN1_NULL,
	ASN1_OBJID,
	ASN1_OBJDESC,
	ASN1_EXT,
	ASN1_REAL,
	ASN1_ENUM,
	ASN1_EMBEDDED,
	ASN1_UTF8STR,
	ASN1_RELOID,
	ASN1_RESV1,
	ASN1_RESV2,
	ASN1_SEQ,
	ASN1_SET,
	ASN1_NUMSTR,
	ASN1_PRINTSTR,
	ASN1_T61STR,
	ASN1_VTEXTSTR,
	ASN1_IA55STR,
	ASN1_UTCTIME,
	ASN1_GENTIME,
	ASN1_GFXSTR,
	ASN1_VISIBLESTR,
	ASN1_GENSTR,
	ASN1_UNISTR,
	ASN1_CHARSTR,
	ASN1_BMPSTR,
	ASN1_LONFFORM
};

/* Only DER is supported so far.. */

enum asn1_types {
	asn1_ber,
	asn1_cer,
	asn1_der,
	asn1_per
};

enum asn1_class {
};

enum asn1_pc {
	asn1_pc_private=0,
	asn1_pc_constructed
};




typedef struct asn1_context_s {

	/* "private data" */ 

	uint8_t *msg;
	int msg_len;
	int ptr;
	int length;

	int as1_type;		/**< BER, CER or DER */
	int (*callback)( int, const struct asn1_context_s *, void * );
} asn1_context_t;



int get_integer();
int get_boolen();
int get_enum();
int get_real();
int get_raw();
int get_str();



/* Error codes */

#define ASN1_SUCCESS		0



void asn1_init();
int asn1_parse();




#endif /* _asn1_parser_h_included */
