CC=gcc
CFLAGS=-Wall -g -std=c99 -O2 -Wp,-D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64 -fexceptions -fstack-protector --param=ssp-buffer-size=4
CFLAGS_E=-Wno-unused-result # Yeah OK...
LDFLAGS=
LIBS=
INCS=

all: decode_frame encode_frame

decode_frame: decode_frame.c ../websocket.h
	$(CC) $(CFLAGS) $(CFLAGS_E) $(LDFLAGS) -o $@ ${@}.c ${INCS} ${LIBS}

encode_frame: encode_frame.c ../websocket.h
	$(CC) $(CFLAGS) $(CFLAGS_E) $(LDFLAGS) -o $@ ${@}.c ${INCS} ${LIBS}

clean:
	rm -f decode_frame encode_frame
