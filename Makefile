############################################################
# Variables setable from the command line:
#
# CCOMPILER (default: clang)
# DEBUG_SYMBOLS (default: DWARF)
# EXTRA_CFLAGS (default: none)
############################################################

TYPES=\
	-DOSE_CONF_PROVIDE_TYPE_DOUBLE \
	-DOSE_CONF_PROVIDE_TYPE_TIMETAG

ifndef CCOMPILER
CC=clang
else
CC=$(CCOMPILER)
endif

ifeq ($(OS),Windows_NT)
OSNAME:=$(OS)
else
OSNAME:=$(shell uname -s)
endif

BASENAME=stdlib

LIBOSE_DIR=../libose

# this produces a var called $LD_UNDEF_FLAGS
ifeq ($(shell uname), Darwin)
include $(LIBOSE_DIR)/ose_linker_flags_macos.mk
else ifeq ($(shell uname), Linux)
include $(LIBOSE_DIR)/ose_linker_flags_linux.mk
endif

MOD_FILES=\
	ose_$(BASENAME).c

INCLUDES=-I. -I$(LIBOSE_DIR)

DEFINES=-DHAVE_OSE_ENDIAN_H \
	-DOSE_GETPAYLOADITEMLENGTH_HOOK=osevm_getPayloadItemLength_hook \
	-DOSE_GETPAYLOADITEMSIZE_HOOK=osevm_getPayloadItemSize_hook \
	-DOSE_PPRINTPAYLOADITEM_HOOK=osevm_pprintPayloadItem_hook

ifeq ($(shell uname), Darwin)
# DEFINES+=-Wl,-U,_osevm_getPayloadItemLength_hook \
# -Wl,-U,_osevm_getPayloadItemSize_hook \
# -Wl,-U,_osevm_pprintPayloadItem_hook
DEFINES+=$(LD_UNDEF_FLAGS)
else ifeq ($(shell uname), Linux)
# DEFINES+=-Wl,-u,_osevm_getPayloadItemLength_hook \
# -Wl,-u,_osevm_getPayloadItemSize_hook \
# -Wl,-u,_osevm_pprintPayloadItem_hook
DEFINES+=$(LD_UNDEF_FLAGS)
endif

CFLAGS_DEBUG=-Wall -DOSE_CONF_DEBUG -O0 -g$(DEBUG_SYMBOLS) $(EXTRA_CFLAGS) $(TYPES)
CFLAGS_RELEASE=-Wall -O3 $(EXTRA_CFLAGS) $(TYPES)

release: CFLAGS+=$(CFLAGS_RELEASE)
release: $(LIBOSE_DIR)/sys/ose_endian.h ose_$(BASENAME).so

debug: CFLAGS+=$(CFLAGS_DEBUG)
debug: $(LIBOSE_DIR)/sys/ose_endian.h ose_$(BASENAME).so

ifeq ($(OS),Windows_NT)
else
CFLAGS:=-fPIC
endif

ose_$(BASENAME).so: $(MOD_FILES) #$(foreach f,$(OSE_CFILES),$(LIBOSE_DIR)/$(f)) 
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -shared -o o.se.$(BASENAME).so $^

$(LIBOSE_DIR)/sys/ose_endian.h:
	cd $(LIBOSE_DIR) && $(MAKE) sys/ose_endian.h

.PHONY: clean
clean:
	rm -rf *.o *.so *.dSYM
