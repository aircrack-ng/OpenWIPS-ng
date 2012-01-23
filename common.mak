CC			?= gcc
CFLAGS		?= -O0 -g3 -pthread -Wall -Werror

prefix		= /usr/local
sbindir		= $(prefix)/sbin
bindir		= $(prefix)/bin
confdir		= $(prefix)/etc/openwips-ng/
mandir		= $(prefix)/man/man1
datadir		= $(prefix)/share
docdir		= $(datadir)/doc/openwips-ng

REVISION	= $(shell ../evalrev)
REV_DEFINE	= -D_REVISION=$(REVISION)