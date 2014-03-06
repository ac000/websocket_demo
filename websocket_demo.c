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
#include <sys/timerfd.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <glib.h>

#include "websocket.h"

#define SERVER_IP		"0.0.0.0"
#define SERVER_PORT		1976

#define MAX_EVENTS		10
#define BUF_SIZE		4096

struct client_state {
	int fd;			/* accept fd */
	int tfd;		/* timer fd */
	char msg[BUF_SIZE + 1];	/* Data from client */
};

static int epollfd;
static struct epoll_event ev;
static struct epoll_event events[MAX_EVENTS];

static GHashTable *timer_to_socket;	/* timer fd to socket fd lookup */
static GHashTable *clients;		/* client_states's key'd on sock fd */

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
	uint64_t len;
	uint64_t plen;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
	int ext_hdr_len = 0;
	ssize_t bytes_wrote;
	struct ifaddrs *ifaddr;
	struct ifaddrs *ifa;
	FILE *fp;

	len = snprintf(tbuf, sizeof(tbuf), "{ ");

	fp = fopen("/etc/hostname", "r");
	fscanf(fp, "%4095s", buf);
	len += snprintf(tbuf + len, sizeof(tbuf) - len, "\"host\": \"%s\", ",
			buf);
	fclose(fp);

	fp = fopen("/proc/uptime", "r");
	fscanf(fp, "%lu", &uptime);
	len += snprintf(tbuf + len, sizeof(tbuf) - len, "\"uptime\": %lu",
			uptime);
	fclose(fp);

	getifaddrs(&ifaddr);
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL ||
		    strcmp(ifa->ifa_name, "lo") == 0 ||
		    ifa->ifa_addr->sa_family != AF_PACKET ||
		    !(ifa->ifa_flags & IFF_UP))
			continue;

		fp = fopen("/proc/net/dev", "r");
		while (fgets(buf, BUF_SIZE, fp)) {
			if (strstr(buf, ifa->ifa_name)) {
				sscanf(buf, "%*[ a-z0-9_-]: "
						"%lu %*d %*d %*d %*d %*d %*d "
						"%*d %lu",
						&rx_bytes, &tx_bytes);
				break;
			}
		}
		fclose(fp);

		len += snprintf(tbuf + len, sizeof(tbuf) - len,
				", \"ifname\": \"%s\", ", ifa->ifa_name);
		len += snprintf(tbuf + len, sizeof(tbuf) - len,
				"\"rx\": %lu, ", (uint64_t)rx_bytes);
		len += snprintf(tbuf + len, sizeof(tbuf) - len,
				"\"tx\": %lu", (uint64_t)tx_bytes);

		break;
	}
	freeifaddrs(ifaddr);

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
 * Creates and/or adjusts the clients update timer
 */
static void set_client_timer(int freq, struct client_state *client)
{
	struct itimerspec its;

	its.it_value.tv_sec = freq;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	if (client->tfd == -1) {
		int fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
		ev.events = EPOLLIN | EPOLLET;
		ev.data.fd = fd;
		epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);

		client->tfd = fd;
		g_hash_table_insert(timer_to_socket, GINT_TO_POINTER(fd),
				GINT_TO_POINTER(client->fd));
	}

	timerfd_settime(client->tfd, 0, &its, NULL);
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
	printf("* opcode     : 0x%02x (%s)\n", wh->opcode,
			websocket_opcodes[wh->opcode]);

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

static size_t read_client_data(struct client_state *client)
{
	ssize_t bytes_read;
	size_t processed = 0;
	char buf[BUF_SIZE + 1];

	bytes_read = read(client->fd, &buf, BUF_SIZE);
	if (bytes_read == -1)
		return -1;
	printf("Received data from client (%ld bytes)\n", bytes_read);
	do {
		int freq;

		memset(client->msg, 0, sizeof(client->msg));
		processed += decode_frame(client->msg, buf + processed);
		if (processed == -1)
			break;
		printf("Client data -:\n\n%s\n", client->msg);
		freq = atoi(client->msg);
		set_client_timer(freq, client);
		printf("Setting client update frequency to %d seconds\n",
				freq);
	} while (processed < bytes_read);

	return processed;
}

static void close_conn(struct client_state *client)
{
	printf("Closing connection on %d\n", client->fd);

	close(client->fd);
	close(client->tfd);
	g_hash_table_remove(timer_to_socket, GINT_TO_POINTER(client->tfd));
	g_hash_table_remove(clients, GINT_TO_POINTER(client->fd));
}

static void new_client(int fd)
{
	ssize_t bytes_read;
	char buf[BUF_SIZE + 1];
	char key[64];
	struct client_state *client;

	printf("New client\n");
	bytes_read = read(fd, &buf, BUF_SIZE);
	if (bytes_read == -1)
		return;
	buf[bytes_read] = '\0';
	printf("Received from client (%ld bytes) ->\n%s\n", bytes_read, buf);

	get_header(key, "Sec-WebSocket-Key:", buf);
//	printf("key    : %s\n", key);

	do_handshake(key, fd);

	client = malloc(sizeof(struct client_state));

	client->fd = fd;
	client->tfd = -1;
	g_hash_table_insert(clients, GINT_TO_POINTER(fd), client);
}

static void handle_socket(struct client_state *client)
{
	int err;

	printf("Got request on %d\n", client->fd);

	err = read_client_data(client);
	if (err == -1) {
		close_conn(client);
		return;
	}

	err = do_response(client->fd);
	if (err == -1)
		 close_conn(client);
}

static void handle_timer(struct client_state *client)
{
	uint64_t tbuf;
	int err;

	read(client->tfd, &tbuf, sizeof(tbuf));
	err = do_response(client->fd);
	if (err == -1)
		close_conn(client);
}

/*
 * Handle one of three different fd's.
 *    1a) An accept(2)'ed file descriptor for a new connection
 *    1b) An already connected socket
 *     2) A timer file descriptor
 */
static void handle_fd(int fd)
{
	gpointer sfd;
	struct client_state *client;

	sfd = g_hash_table_lookup(timer_to_socket, GINT_TO_POINTER(fd));
	if (sfd) {
		/* Timer fd */
		client = g_hash_table_lookup(clients, sfd);
		handle_timer(client);
	} else {
		client = g_hash_table_lookup(clients, GINT_TO_POINTER(fd));
		if (client)
			handle_socket(client);
		else
			new_client(fd);
	}
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

	clients = g_hash_table_new_full(NULL, NULL, NULL, free);
	timer_to_socket = g_hash_table_new(NULL, NULL);

	/* Don't terminate on -EPIPE */
	signal(SIGPIPE, SIG_IGN);

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
