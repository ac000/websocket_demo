/*
 * decode_frame.c - Decode a WebSocket frame header
 *
 * Copyright (C) 2014, 2018   Andrew Clayton <andrew@digital-domain.net>
 *
 * Licensed under the GNU General Public License Version 2
 * See COPYING
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#include "../websocket.h"

#define BUF_SIZE	8192

static int frame_nr;

static size_t decode_frame_header(const char *src)
{
	size_t moffset;
	uint64_t plen;
	unsigned char key[MKEY_LEN];
	struct websocket_header *wh;

	wh = (struct websocket_header *)src;

	printf("Frame : %d\n", ++frame_nr);

	printf("\tFIN            : %d\n", wh->fin);
	printf("\tRSV1           : %d\n", wh->rsv1);
	printf("\tRSV2           : %d\n", wh->rsv2);
	printf("\tRSV3           : %d\n", wh->rsv3);
	printf("\tOpcode         : 0x%02x (%s)\n", wh->opcode,
			websocket_opcodes[wh->opcode]);
	printf("\tMasked         : %d\n", wh->masked);

	if (wh->pay_len <= PAYLEN_LEN) {
		moffset = SHORT_HDR_LEN;
		plen = wh->pay_len;
	} else if (wh->pay_len == PAYLEN_LEN16) {
		moffset = sizeof(uint16_t) + SHORT_HDR_LEN;
		plen = ntohs(*(uint16_t *)(src + SHORT_HDR_LEN));
	} else {
		moffset = sizeof(uint64_t) + SHORT_HDR_LEN;
		plen = be64toh(*(uint64_t *)(src + SHORT_HDR_LEN));
	}

	if (wh->masked) {
		memcpy(key, src + moffset, MKEY_LEN);
		printf("\tMask key       : 0x%02x 0x%02x 0x%02x 0x%02x\n",
			key[0], key[1], key[2], key[3]);
	} else {
		moffset = 0;
	}

	printf("\tPayload length : %lu\n", plen);

	return moffset + MKEY_LEN + plen;
}

int main(int argc, char *argv[])
{
	int fd;
	char buf[BUF_SIZE];

	if (argc < 2) {
		printf("Usage: decode_frame <file>\n");
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_RDONLY);
	read(fd, &buf, MAX_HDR_LEN);
	close(fd);
	decode_frame_header(buf);

	exit(EXIT_SUCCESS);
}
