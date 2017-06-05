bin_PROGRAMS = miio_dispatcher dispatcher_client
miio_dispatcher_SOURCES = src/miio_dispatcher.c src/miio_json.c src/miio_json.h src/miio_dispatcher.h

dispatcher_client_SOURCES = src/dispatcher_client.c

miio_dispatcher_LDADD = $(jsonc_LIBS) -ljson-c -lm
miio_dispatcher_CFLAGS = -I. $(jsonc_CFLAGS) -s

dispatcher_client_CFLAGS = -s

distclean-local:
	rm -rf Makefile.in compile autom4te.cache aclocal.m4 config.h.in configure depcomp install-sh missing
