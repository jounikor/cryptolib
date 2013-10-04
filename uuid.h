#ifndef _uuid_h_included
#defne _uuid_h_included

/**
 * \file uuid.h
 * \brief A header file for RFC4122 UUID handling. 
 * \author Jouni Korhonen
 * \email jouni.korhonen@iki.fi
 * \version 0.1 (initial)
 * \date 2013-9-30
 * \copyright Not GPL
 *
 *
 */


#include <stdint.h>


enum UUID_version_e {
	UUID_version_1 = 1,
	UUID_version_2,
	UUID_version_3,
	UUID_version_4,
	UUID_version_5
};

typedef struct uuid_s {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	unint8_t clock_seq_hi_and_reserved;
	unint8_t clock_seq_low;
	uint8_t node[6];

} uuid_t;

#define UUID_VERSION_MASK 0xf000


int uuid_create_version_1( uuid_t *, int,  );
int uuid_create_version_2( uuid_t *, int,  );
int uuid_create_version_3( uuid_t *, int,  );
int uuid_create_version_4( uuid_t *, int,  );
int uuid_create_version_5( uuid_t *, int,  );





#endif /* _uuid_h_included */
