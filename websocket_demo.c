/*
 * websocket_demo.c
 *
 * WebSockets are defined here: http://tools.ietf.org/html/rfc6455
 *
 * Copyright (C) 2014	Andrew Clayton <andrew@digital-domain.net>
 *
 * Licensed under the GNU General Public License Version 2
 * See COPYING
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <glib.h>

#include "websocket.h"

#define SERVER_IP		"0.0.0.0"
#define SERVER_PORT		1976

#define MAX_CLIENTS		10
#define MAX_EVENTS		10
#define BUF_SIZE		4096

struct client_state {
	int fd;			/* accept fd */
	int update_freq;	/* How often to get updates (in seconds) */
	int time_rem;		/* Seconds left before update */
	char msg[BUF_SIZE + 1];	/* Data from client */
};
static struct client_state clients[MAX_CLIENTS];

static int epollfd;
static struct epoll_event ev;
static struct epoll_event events[MAX_EVENTS];

#define NET_IF	"p17p1"
/*
 * Builds some JSON with some system information and sends that to the client
 */
static ssize_t do_response(int fd)
{
	struct websocket_header wh = {  .opcode = 0x01, .rsv3 = 0, .rsv2 = 0,
					.rsv1 = 0, .fin = 1, .masked = 0 };
	char buf[BUF_SIZE];
	char tbuf[BUF_SIZE];
	unsigned long uptime;
	unsigned long rx;
	unsigned long tx;
	uint64_t len;
	uint64_t plen;
	int ext_hdr_len = 0;
	ssize_t bytes_wrote;
	FILE *fp;

	len = snprintf(tbuf, sizeof(tbuf), "{ ");

	fp = fopen("/etc/hostname", "r");
	fscanf(fp, "%4095s", buf);
	len += snprintf(tbuf + len, sizeof(tbuf) - len, "\"host\": \"%s\", ",
			buf);
	fclose(fp);

	fp = fopen("/proc/uptime", "r");
	fscanf(fp, "%lu", &uptime);
	len += snprintf(tbuf + len, sizeof(tbuf) - len, "\"uptime\": %lu, ",
			uptime);
	fclose(fp);

	fp = fopen("/proc/net/dev", "r");
	do {
		fgets(buf, BUF_SIZE, fp);
		if (strstr(buf, NET_IF)) {
			sscanf(buf, " "NET_IF": "
					"%lu %*d %*d %*d %*d %*d %*d %*d %lu",
					&rx, &tx);
			break;
		}
	} while (!feof(fp));
	len += snprintf(tbuf + len, sizeof(tbuf) - len, "\"rx\": %lu, ", rx);
	len += snprintf(tbuf + len, sizeof(tbuf) - len, "\"tx\": %lu", tx);
	fclose(fp);

	len += snprintf(tbuf + len, sizeof(tbuf) - len, " }");

	/* Set the extra payload length header if required */
	if (len <= PAYLEN_LEN) {
		wh.pay_len = len;
	} else if (len <= UINT16_MAX) {
		wh.pay_len = PAYLEN_LEN16;
		plen = htons((uint16_t)len);
		ext_hdr_len = sizeof(uint16_t);
	} else {
		wh.pay_len = PAYLEN_LEN64;
		plen = len;
		ext_hdr_len = sizeof(uint64_t);
	}

	memcpy(buf, &wh, SHORT_HDR_LEN);
	if (len > PAYLEN_LEN)
		memcpy(buf + SHORT_HDR_LEN, &plen, ext_hdr_len);
	memcpy(buf + SHORT_HDR_LEN + ext_hdr_len, tbuf, len);
	bytes_wrote = write(fd, buf, SHORT_HDR_LEN + ext_hdr_len + len);

	return bytes_wrote;
}

/*
 * This is likely not async-signal safe
 */
static void sh_do_response(int sig, siginfo_t *si, void *uc)
{
	int i;

	for (i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].fd != -1) {
			clients[i].time_rem--;
			if (clients[i].time_rem == 0) {
				ssize_t err = do_response(clients[i].fd);
				if (err == -1) {
					close(clients[i].fd);
					clients[i].fd = -1;
					continue;
				}
				clients[i].time_rem = clients[i].update_freq;
			}
		}
	}
}

/*
 * The tricky bit here is we need to :-
 *     1) Append the UUID websocket key defined in the spec to the
 *        key sent by the client.
 *     2) Create a SHA1 digest (i.e not the normal hex string) of
 *        the above.
 *     3) Base64 encode the SHA1
 */
static void do_handshake(const char *key, int fd)
{
	char buf[BUF_SIZE];
	char *base64;
	gsize len = g_checksum_type_get_length(G_CHECKSUM_SHA1);
	guint8 *buffer = g_new(guint8, len);
	GChecksum *csum;

	len = snprintf(buf, sizeof(buf), "%s%s", key, WS_KEY);
	csum = g_checksum_new(G_CHECKSUM_SHA1);
	g_checksum_update(csum, (unsigned char *)buf, -1);
	g_checksum_get_digest(csum, buffer, &len);
	base64 = g_base64_encode(buffer, len);
//	printf("base64 : %s\n", base64);

	len = snprintf(buf, sizeof(buf),
			"HTTP/1.1 101 Switching Protocols\r\n"
			"Upgrade: websocket\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Accept: %s\r\n\r\n", base64);
	write(fd, buf, len);

	g_free(base64);
	g_free(buffer);
	g_checksum_free(csum);
}

/*
 * Given a header string, return its value
 */
static void get_header(char *dest, const char *header, const char *data)
{
	char *p;

	p = strstr(data, header);
	p = strchr(p, ' ');
	p++;
	while (!isspace(*p))
		*dest++ = *p++;
	*dest = '\0';
}

static ssize_t decode_frame(char *dest, const char *src)
{
	size_t moffset;
	size_t processed;
	uint64_t i;
	uint64_t plen;
	unsigned char key[MKEY_LEN];
	struct websocket_header *wh;

	wh = (struct websocket_header *)src;
	printf("* FIN        : %d\n", wh->fin);
	printf("* RSV1       : %d\n", wh->rsv1);
	printf("* RSV2       : %d\n", wh->rsv2);
	printf("* RSV3       : %d\n", wh->rsv3);
	printf("* opcode     : 0x%02x\n", wh->opcode);

	/* Did we get a connection close request? */
	if (wh->opcode == 0x08)
		return -1;

	if (wh->pay_len <= PAYLEN_LEN) {
		moffset = SHORT_HDR_LEN;
		plen = wh->pay_len;
	} else if (wh->pay_len == PAYLEN_LEN16) {
		moffset = sizeof(uint16_t) + SHORT_HDR_LEN;
		plen = ntohs(*(uint16_t *)(src + SHORT_HDR_LEN));
	} else {
		moffset = sizeof(uint64_t) + SHORT_HDR_LEN;
		plen = *(uint64_t *)(src + SHORT_HDR_LEN);
	}
	printf("* len        : %lu\n", plen);

	/* Decode the payload data */
	memcpy(key, src + moffset, MKEY_LEN);
	for (i = 0; i < plen; i++)
		dest[i] = src[i + moffset + MKEY_LEN] ^ key[i % MKEY_LEN];

	processed = moffset + MKEY_LEN + plen;
	printf("* processed  : %lu\n", processed);

	return processed;
}

static size_t read_client_data(int fd, struct client_state *client)
{
	ssize_t bytes_read;
	size_t processed = 0;
	char buf[BUF_SIZE + 1];

	bytes_read = read(fd, &buf, BUF_SIZE);
	if (bytes_read == -1)
		return -1;
	printf("Received data from client (%ld bytes)\n", bytes_read);
	do {
		memset(client->msg, 0, sizeof(client->msg));
		processed += decode_frame(client->msg, buf + processed);
		if (processed == -1)
			break;
		printf("Client data -:\n\n%s\n", client->msg);
		client->update_freq = atoi(client->msg);
		if (client->update_freq <= 0)
			client->update_freq = 5;
		client->time_rem = client->update_freq;
		printf("Setting client update frequency to %d seconds\n",
				client->update_freq);
	} while (processed < bytes_read);

	return processed;
}

static void handle_fd(int fd)
{
	int i;
	ssize_t bytes_read;
	ssize_t err;
	char buf[BUF_SIZE + 1];
	char key[64];

	printf("Got connection on %d\n", fd);

	for (i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].fd == fd) {
			err = read_client_data(fd, &clients[i]);
			if (err == -1) {
				printf("Closing connection on %d\n", fd);
				close(fd);
				clients[i].fd = -1;
				clients[i].update_freq = -1;
				return;
			}
			do_response(fd);
			return;
		}
	}

	printf("New client\n");
	bytes_read = read(fd, &buf, BUF_SIZE);
	if (bytes_read == -1)
		return;
	buf[bytes_read] = '\0';
	printf("Received from client (%ld bytes) ->\n%s\n", bytes_read, buf);

	get_header(key, "Sec-WebSocket-Key:", buf);
//	printf("key    : %s\n", key);

	do_handshake(key, fd);

	for (i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].fd == -1) {
			clients[i].fd = fd;
			break;
		}
	}
}

/*
 * Create a timer (every second) to check for clients that need updates.
 */
static void init_timer(void)
{
	timer_t timerid;
	struct sigevent sev;
	struct itimerspec its;
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_sigaction = sh_do_response;
	sigaction(SIGRTMIN, &sa, NULL);

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGRTMIN;
	sev.sigev_value.sival_ptr = &timerid;
	timer_create(CLOCK_MONOTONIC, &sev, &timerid);

	its.it_value.tv_sec = 1;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	timer_settime(timerid, 0, &its, NULL);
}

int main(int argc, char *argv[])
{
	int i;
	int timeout = -1;
	int lfd;
	socklen_t server_len;
	struct sockaddr_in server_address;

	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr(SERVER_IP);
	server_address.sin_port = htons(SERVER_PORT);
	server_len = sizeof(server_address);

	lfd = socket(server_address.sin_family, SOCK_STREAM, 0);
	i = 1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
	bind(lfd, (struct sockaddr *)&server_address, server_len);
	listen(lfd, 5);

	epollfd = epoll_create1(0);
	ev.events = EPOLLIN;
	ev.data.fd = lfd;
	epoll_ctl(epollfd, EPOLL_CTL_ADD, lfd, &ev);

	for (i = 0; i < MAX_CLIENTS; i++)
		clients[i].fd = -1;

	/* Don't terminate on -EPIPE */
	signal(SIGPIPE, SIG_IGN);
	init_timer();

	for (;;) {
		int n;
		int nfds;
		int cfd;

		nfds = epoll_wait(epollfd, events, MAX_EVENTS, timeout);
		for (n = 0; n < nfds; n++) {
			if (events[n].data.fd == lfd) {
				cfd = accept4(lfd, NULL, NULL, O_NONBLOCK);

				ev.events = EPOLLIN | EPOLLET;
				ev.data.fd = cfd;
				epoll_ctl(epollfd, EPOLL_CTL_ADD, cfd, &ev);
			} else {
				handle_fd(events[n].data.fd);
			}
		}
	}
}
