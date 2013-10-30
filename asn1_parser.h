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
	ASN1_ENUM,          /* 0x0a */
	ASN1_EMBEDDED,
	ASN1_UTF8STR,
	ASN1_RELOID,
	ASN1_RESV1,
	ASN1_RESV2,
	ASN1_SEQ,           /* 0x10 */
	ASN1_SET,
	ASN1_NUMSTR,
	ASN1_PRINTSTR,
	ASN1_T61STR,
	ASN1_VTEXTSTR,
	ASN1_IA55STR,
	ASN1_UTCTIME,
	ASN1_GENTIME,
	ASN1_GFXSTR,
	ASN1_VISIBLESTR,    /* 0x1a */
	ASN1_GENSTR,
	ASN1_UNISTR,
	ASN1_CHARSTR,
	ASN1_BMPSTR,
	ASN1_LONGFORM       /* 0x1f */
};

/* Only DER is supported so far.. */

enum asn1_types {
	asn1_ber,
	asn1_cer,
	asn1_der,
	asn1_per
};

enum asn1_class {
    asn1_class_universal    = 0x00,
    asn1_class_application  = 0x40,
    asn1_class_context      = 0x80,   /* default */
    asn1_class_private      = 0xc0
};

enum asn1_pc {
	asn1_pc_private     = 0x00,
	asn1_pc_constructed = 0x20
};


typedef struct asn1_context_s {
    int tag;
    int len;

	/* "private data" */ 

    char infinite;
    char constructed;
    char class;
    char pad;


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

#define ASN1_SUCCESS		        0
#define ASN1_ERROR_TYPE             1   /* wrong type (ber,cer,der) */
#define ASN1_ERROR_INVALID_VALUE    2   /* something wrong with the value */
#define ASN1_ERROR_INFINITE_FORM    3   /* only definitive length encoding supported */
#define ASN1_ERROR_TOO_LONG         4   /* length too big for the imlementation to handle */
#define ASN1_ERROR_INVALID_MESSAGE  5   /* broken ASN1 message encoding e.g. too short */
#dedine ASN1_ERROR_LONG_FORM		7	/* long form tag values are not supported */
#define ASN1_ERROR_INVALID_TAG      8   /* tag is too long */

void asn1_init();
int asn1_parse();




#endif /* _asn1_parser_h_included */
