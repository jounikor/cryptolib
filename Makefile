#
# (c) 20xx Jouni 'Mr.Spiv' Korhonen / Dead Coders Society
# jouni.korhonen@iki.fi
#

.PHONY: clean all dep dist dec
.SUFFIXES:
.SUFFIXES: .c .o .h .asm .p .c
.DEFAULT:
	make all
#

SRCS = hmac.c sha1.c bignum.c uuid.c rand.c md5.c

OBJS := $(patsubst %.c,%.o,$(SRCS))

HDRS = hmac.h sha1.h algorithm_types.h crypto_error.h bignum.h \
       uuid.h rand.h synchronization.h md5.h

#

PROG = hmac

CC := gcc
RM := rm -f
CP := cp
CPU :=
OS :=
DEPEND := .dep
WILD := *

LOCAL_CFLAGS = -DPARTOFLIBRARY -fomit-frame-pointer -g
#LOCAL_CFLAGS = -fomit-frame-pointer -O -DWORD_ALIGNMENT
LOCAL_LDFLAGS =
#LOCAL_LDFLAGS = -lstdc++

#
#
#

ifeq ($(OS),AMIGA)
	LOCAL_CFLAGS += -DWORD_ALIGNMENT
#	LOCAL_CFLAGS += -noixemul
	RM = delete
	WILD = "\#?"

ifeq ($(CPU),68020)
	LOCAL_CFLAGS += -mc68020
endif
endif

#
# rules

all: $(DEPEND) $(PROG)
#	@echo $(FOO)
	

ifeq ($(DEPEND),$(wildcard $(DEPEND)))
include $(DEPEND)
endif

$(DEPEND): Makefile
	$(CC) -MM $(SRCS) > $(DEPEND)
	@echo "Dependencies done"


%.o: %.c
	$(CC) $(LOCAL_CFLAGS) -c $< -o $@

#
#
#

$(PROG): $(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(LOCAL_LIBDIR) $(LOCAL_LIBS) $(LOCAL_LDFLAGS)


clean:
	-$(RM) $(WILD).o
	-$(RM) $(WILD)~
	-$(RM) $(PROG).tgz
	-$(RM) $(DEPEND)
	-$(RM) $(PROG)

dist:
	tar zcvf $(PROG).tgz *.h *.c Makefile readme.txt




