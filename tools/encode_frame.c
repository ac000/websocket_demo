/* SPDX-License-Identifier: MIT */

/*
 * encode_frame.c - Create a WebSocket frame header
 *
 * Copyright (C) 2014, 2018	Andrew Clayton <andrew@digital-domain.net>
 */

#define _XOPEN_SOURCE		/* for getopt(3) */

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

#define OUT_FILE	"ws_hdr.bin"
#define BUF_SIZE	4096

struct websocket_frame {
	struct websocket_header wh;

	uint32_t key;
	uint64_t len;
};

static void disp_usage(void)
{
	printf("Usage: encode_frame [-f 0|1] [-1 0..9] [-2 0..9] [-3 0..9] "
			"[-o 0x0..0xf] [-m 0|1] [-p 0..UINT64_MAX] "
			"[-k 0..UINT32_MAX] [-h]\n");
	printf("\n");
	printf("  -f FIN\n");
	printf("  -1 RSV1\n");
	printf("  -2 RSV2\n");
	printf("  -3 RSV3\n");
	printf("  -o Opcode\n");
	printf("  -m Masked\n");
	printf("  -p Payload Length\n");
	printf("  -k Masking Key\n");
	printf("  -h This help text\n");
	exit(EXIT_SUCCESS);
}

static void encode_frame_header(struct websocket_frame *wf)
{
	int fd;
	int ext_hdr_len = 0;
	uint64_t plen;
	char buf[BUF_SIZE];

	if (wf->len <= PAYLEN_LEN) {
		wf->wh.pay_len = wf->len;
	} else if (wf->len <= UINT16_MAX) {
		wf->wh.pay_len = PAYLEN_LEN16;
		plen = htons((uint16_t)wf->len);
		ext_hdr_len = sizeof(uint16_t);
	} else {
		wf->wh.pay_len = PAYLEN_LEN64;
		plen = htonl(wf->len);
		ext_hdr_len = sizeof(uint64_t);
	}

	memcpy(buf, &wf->wh, SHORT_HDR_LEN);
	if (wf->len > PAYLEN_LEN)
		memcpy(buf + SHORT_HDR_LEN, &plen, ext_hdr_len);

	if (wf->wh.masked) {
		memcpy(buf + SHORT_HDR_LEN + ext_hdr_len, &wf->key, MKEY_LEN);
		ext_hdr_len += MKEY_LEN;
	}

	fd = open(OUT_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	write(fd, buf, SHORT_HDR_LEN + ext_hdr_len);
	close(fd);
}

int main(int argc, char *argv[])
{
	int opt;
	struct websocket_frame wf = { .wh.fin = 1, .wh.rsv1 = 0, .wh.rsv2 = 0,
				      .wh.rsv3 = 0, .wh.opcode = 0x1,
				      .wh.masked = 0,
				      .key = 0, .len = 125 };

	while ((opt = getopt(argc, argv, "f:1:2:3:o:m:p:k:h")) != -1) {
		switch (opt) {
		case 'f':
			if ((optarg[0] != '0' && optarg[0] != '1') ||
			    strlen(optarg) > 1)
				disp_usage();
			else
				wf.wh.fin = atoi(optarg);
			break;
		case '1':
			if (strlen(optarg) > 1)
				disp_usage();
			else
				wf.wh.rsv1 = atoi(optarg);
			break;
		case '2':
			if (strlen(optarg) > 1)
				disp_usage();
			else
				 wf.wh.rsv2 = atoi(optarg);
			break;
		case '3':
			if (strlen(optarg) > 1)
				disp_usage();
			else
				wf.wh.rsv3 = atoi(optarg);
			break;
		case 'o':
			if (strtoul(optarg, NULL, 16) < 0x0 ||
			    strtoul(optarg, NULL, 16) > 0xf)
				disp_usage();
			else
				wf.wh.opcode = strtoul(optarg, NULL, 16);
			break;
		case 'm':
			if ((optarg[0] != '0' && optarg[0] != '1') ||
			    strlen(optarg) > 1)
				disp_usage();
			else
				wf.wh.masked = atoi(optarg);
			break;
		case 'p':
			if (strtoul(optarg, NULL, 10) < 0)
				disp_usage();
			else
				wf.len = strtoul(optarg, NULL, 10);
			break;
		case 'k':
			wf.key = strtoul(optarg, NULL, 10);
			break;
		case 'h':
			disp_usage();
			break;
		}
	}

	encode_frame_header(&wf);

	exit(EXIT_SUCCESS);
}
