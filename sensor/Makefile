CC			?= gcc
CFLAGS		?= -O0 -g3 -pthread -Wall -Werror
LIBS		= -lpcap -lm -lpthread

prefix		= /usr/local
sbindir		= $(prefix)/sbin

SBIN_FILE	= openwips-ng

ifeq ($(DEBUG), yes)
	CFLAGS	+= -DDEBUG 
endif

ifeq ($(DEBUG), normal)
	CFLAGS	+= -DDEBUG 
endif

ifeq ($(DEBUG), true)
	CFLAGS	+= -DDEBUG 
endif

ifeq ($(DEBUG), extra)
	CFLAGS	+= -DDEBUG -DEXTRA_DEBUG
endif

default: all

all: openwips-ng

openwips-ng:
	$(CC) $(CFLAGS) $(LIBS) -o $(SBIN_FILE) main.c client.c structures.c packet_capture.c command_parse.c rpcap.c common/pcap.c common/client.c common/server-client.c common/sockets.c global_var.c common/rpcap.c common/utils.c

strip:
	strip $(SBIN_FILE)

install: openwips-ng
	install -m 755 $(SBIN_FILE) $(sbindir)

uninstall:
	rm $(sbindir)/$(SBIN_FILE)

clean:
	-rm -f *.o common/*.o $(SBIN_FILE)
