CC=gcc
CFLAGS=-Wall -Wextra -Wdeclaration-after-statement -Wvla -g -std=c99 -O2 -Wp,-D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -fPIE
CFLAGS_E=-Wno-unused-result # Yeah OK...
LDFLAGS=-Wl,-z,now,-z,defs,-z,relro,--as-needed -pie
LIBS=-lssl -lcrypto

ifeq ($(shell pkg-config --exists libseccomp && echo 1), 1)
LIBS += -lseccomp
CFLAGS += -D_HAVE_LIBSECCOMP
endif

websocket_demo: websocket_demo.c websocket.h
	$(CC) $(CFLAGS) $(CFLAGS_E) $(LDFLAGS) -o $@ ${@}.c ${LIBS}

clean:
	rm -f websocket_demo
