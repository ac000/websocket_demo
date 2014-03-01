CC=gcc
CFLAGS=-Wall -g -std=c99 -O2 -Wp,-D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -fPIE
CFLAGS_E=-Wno-unused-result # Yeah OK...
LDFLAGS=-Wl,-z,now -pie
LIBS=`pkg-config --libs glib-2.0`
INCS=`pkg-config --cflags glib-2.0`

websocket_demo: websocket_demo.c websocket.h
	$(CC) $(CFLAGS) $(CFLAGS_E) $(LDFLAGS) -o $@ ${@}.c ${INCS} ${LIBS}

clean:
	rm -f websocket_demo
