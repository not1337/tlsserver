# This file is part of the tlsserver project
# 
# (C) 2020 Andreas Steinmetz, ast@domdv.de
# The contents of this file is licensed under the GPL version 2 or, at
# your choice, any later version of this license.
#
# =============================================================================
#
# select any or all of the following libraries (select at least one)
#
# OpenSSL 1.1 or later
#
OPENSSL=1
#
# GnuTLS 3.5 or later
#
GNUTLS=1
#
# enable to allow session ticket usage (requires pthread mutex)
#
ENABLE_TICKETS=1
#
# enable to allow OCSP response cacheing (requires pthread mutex)
#
OCSP_CACHE=1
#
# define if you want to test http2 data transfer
#
HTTP2=1
#
# installation directories for library and header file
#
LIBDIR=/usr/local/lib64
HDRDIR=/usr/local/include
#
# compiler and flags
#
CC=gcc
CFLAGS=-O2
LFLAGS=-s
#
# enable the to actually remove all unreferenced code:
#
CFLAGS+=-fdata-sections -ffunction-sections
LFLAGS+=-Wl,-gc-sections
#
# enable to enable the link time optimizer
#
CFLAGS+=-flto
LFLAGS+=-flto -fuse-linker-plugin
#
# =============================================================================
#                  no user selectable stuff below this line
# =============================================================================
#
LIBS=
LIBOBJS=tlsserver-common.lo
LIBTST=
LIBVER=1
SOFLAGS=-Wl,-soname,libtlsserver.so.$(LIBVER)
ifdef OPENSSL
SSLWRAP=1
CFLAGS+=-DUSE_OPENSSL
LIBS+=-lssl -lcrypto
LIBOBJS+=tlsserver-openssl.lo
endif
ifdef GNUTLS
SSLWRAP=1
CFLAGS+=-DUSE_GNUTLS
LIBS+=-lgnutls
LIBOBJS+=tlsserver-gnutls.lo
endif
ifdef SSLWRAP
TARGETS=libtlsserver.so tester
else
$(error error no tls library selected!)
endif
ifdef ENABLE_TICKETS
CFLAGS+=-DENABLE_TICKETS
PTHREADS=1
endif
ifdef OCSP_CACHE
CFLAGS+=-DOCSP_CACHE
PTHREADS=1
endif
ifdef PTHREADS
LIBS+=-lpthread
endif
ifdef HTTP2
CFLAGS+=-DHTTP2
LIBTST=-lnghttp2 -lpthread
endif

all: $(TARGETS)

tester: tester.o
	$(CC) $(LFLAGS) -o $@ $< -L. -ltlsserver -Wl,-rpath,. $(LIBTST)

libtlsserver.so: $(LIBOBJS)
	$(CC) $(LFLAGS) $(SOFLAGS) -shared -Wl,--version-script,tlsserver.map \
		-o $@ $(LIBOBJS) $(LIBS)
	ln -sf $@ $@.$(LIBVER)

install: all
	install -m 755 libtlsserver.so $(LIBDIR)/libtlsserver.so.$(LIBVER)
	ln -sf libtlsserver.so.$(LIBVER) $(LIBDIR)/libtlsserver.so
	install -m 644 tlsserver.h $(HDRDIR)/tlsserver.h

clean:
	rm -f libtlsserver.so *.lo *.o tester libtlsserver.so.$(LIBVER)

tester.o: tester.c tlsserver.h
tlsserver-common.lo: tlsserver-common.c tlsdispatch.h tlsserver.h
tlsserver-openssl.lo: tlsserver-openssl.c tlsdispatch.h tlsserver.h
tlsserver-gnutls.lo: tlsserver-gnutls.c tlsdispatch.h tlsserver.h

%.lo : %.c
	$(CC) -fPIC -Wall $(CFLAGS) -o $*.lo -c $<

%.o : %.c
	$(CC) -Wall $(CFLAGS) -c $<
