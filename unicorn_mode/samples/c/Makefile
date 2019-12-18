# Unicorn Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2015

UNAME_S := $(shell uname -s)

LIBDIR = ../../unicorn
BIN_EXT =
AR_EXT = a

# Verbose output?
V ?= 0

CFLAGS += -Wall -Werror -I../../unicorn/include

LDFLAGS += -L$(LIBDIR) -lpthread -lm
ifeq ($(UNAME_S), Linux)
LDFLAGS += -lrt
endif

ifneq ($(CROSS),)
CC = $(CROSS)gcc
endif

.PHONY: all clean

all: harness

clean:		
	rm -rf *.o harness harness-debug

harness.o: harness.c ../../unicorn/include/unicorn/*.h
	${CC} ${CFLAGS} -O3 -c $<

harness-debug.o: harness.c ../../unicorn/include/unicorn/*.h
	${CC} ${CFLAGS} -g -c $< -o $@

harness: harness.o
	${CC} -L${LIBDIR} $< ../../unicorn/libunicornafl.a $(LDFLAGS) -o $@

debug: harness-debug.o
	${CC} -L${LIBDIR} $< ../../unicorn/libunicornafl.a $(LDFLAGS) -o harness-debug
