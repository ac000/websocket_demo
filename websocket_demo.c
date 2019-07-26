/* SPDX-License-Identifier: MIT */

/*
 * websocket_demo.c
 *
 * WebSockets are defined here: http://tools.ietf.org/html/rfc6455
 *
 * Copyright (C) 2014 - 2016, 2018 - 2019	Andrew Clayton
 *						<andrew@digital-domain.net>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#ifdef _HAVE_LIBSECCOMP
#include <seccomp.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "short_types.h"

#include "websocket.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define TLS_server_method       SSLv23_server_method
#endif

#define WS_PORT			"1975"
#define WSS_PORT		"1976"

#define MAX_EVENTS		10
#define BUF_SIZE		4096

#define WS_KEY_LEN		36

#define err_exit(func)	\
	do { \
		perror(func); \
		exit(EXIT_FAILURE); \
	} while (0)

enum conn_type {
	WS_LISTEN = 0,
	WSS_LISTEN,
	WS_CONN,
	WSS_CONN,
	WS_TIMER
};

struct ep_data {
	int fd;
	enum conn_type type;

	union {
		struct {
			char msg[BUF_SIZE + 1];  /* Data from client */
			char rbuf[BUF_SIZE + 1]; /* raw client buffer */
			char net_if[32];
			char peerip[INET6_ADDRSTRLEN];
			bool tls_conn;
			bool connected_ws;
			SSL *tls;

			struct ep_data *timer;
		} conn;

		struct timer {
			struct ep_data *conn;
		} timer;
	} fdt;
};

static const struct listen_on {
	const char *ip;
	const char *port;
} listen_on[] = {
	{ "127.0.0.1", WS_PORT },
	{ "127.0.0.1", WSS_PORT },
	{ "::1", WS_PORT },
	{ "::1", WSS_PORT }
};

static SSL_CTX *tls_ctx;
static const char *TLS_CERT = "wsd.pem";
static const char *TLS_KEY = "wsd.key";

static int epollfd;
static struct epoll_event events[MAX_EVENTS];

static char hostname[HOST_NAME_MAX + 1];
static char def_net_if[32] = "lo";

static void init_seccomp(void)
{
#ifdef _HAVE_LIBSECCOMP
	int err;
	scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_ERRNO(EACCES));
	if (ctx == NULL)
		goto no_seccomp;

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0);

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_create), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(timerfd_settime), 0);

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

	/* Needed for getifaddrs(3) */
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
			 SCMP_CMP(0, SCMP_CMP_EQ, AF_NETLINK));
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockname), 0);

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigreturn), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);

	err = seccomp_load(ctx);
	if (!err) {
		printf("Initialised seccomp\n");
		seccomp_release(ctx);
		return;
	}

no_seccomp:
	seccomp_release(ctx);
	printf("Seccomp initialisation failed. Check kernel config?\n");
#else
	printf("Not built with libseccomp support. Not using seccomp\n");
#endif
}

static int init_tls(void)
{
	int err;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_library_init();
#endif
	SSL_load_error_strings();

	/* Create SSL ctx */
	tls_ctx = SSL_CTX_new(TLS_server_method());
	if (!tls_ctx) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	/* Configure SSL ctx */
	SSL_CTX_set_ecdh_auto(tls_ctx, 1);
	/* Set the key and cert */
	err = SSL_CTX_use_certificate_file(tls_ctx, TLS_CERT, SSL_FILETYPE_PEM);
	if (err <= 0) {
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(tls_ctx);
		return -1;
	}

	err = SSL_CTX_use_PrivateKey_file(tls_ctx, TLS_KEY, SSL_FILETYPE_PEM);
	if (err <= 0) {
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(tls_ctx);
		return -1;
	}

	return 0;
}

/*
 * This is just a demo. No need to get too fancy here, Just catch when
 * we *need* to read/write again.
 */
static ssize_t net_read(struct ep_data *conn, void *buf, size_t count)
{
	ssize_t ret;
	ssize_t bytes_read = 0;

	if (conn->type == WSS_CONN) {
		for (;;) {
			ret = SSL_read(conn->fdt.conn.tls, buf + bytes_read,
				       count - bytes_read);
			if (ret > 0)
				bytes_read += ret;
			else
				return bytes_read;
		}
	}

	do {
		ret = recv(conn->fd, buf + bytes_read, count - bytes_read, 0);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			else if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			else
				return -1;
		}
		bytes_read += ret;
	} while (ret > 0);

	return bytes_read;
}

static ssize_t net_write(struct ep_data *conn, void *buf, size_t count)
{
	ssize_t ret;
	ssize_t bytes_wrote = 0;

	if (conn->type == WSS_CONN) {
		for (;;) {
			ret = SSL_write(conn->fdt.conn.tls, buf + bytes_wrote,
					count - bytes_wrote);
			if (ret > 0)
				bytes_wrote += ret;
			else
				return bytes_wrote;
		}
	}

	do {
		ret = send(conn->fd, buf + bytes_wrote, count - bytes_wrote,
			   0);
		if (ret == 0)
			return bytes_wrote;
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			else if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			else
				return -1;
		}
		bytes_wrote += ret;
	} while (ret > 0);

	return bytes_wrote;
}

static void set_def_net_if(void)
{
	struct ifaddrs *ifaddr;
	struct ifaddrs *ifa;

	getifaddrs(&ifaddr);
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL ||
		    strcmp(ifa->ifa_name, "lo") == 0 ||
		    ifa->ifa_addr->sa_family != AF_PACKET ||
		    !(ifa->ifa_flags & IFF_RUNNING))
			continue;

		snprintf(def_net_if, sizeof(def_net_if), "%s", ifa->ifa_name);
		break;
	}
	freeifaddrs(ifaddr);
}

static void get_stats(const char *net_if, unsigned long *uptime, u64 *rx,
		      u64 *tx)
{
	char path[PATH_MAX];
	FILE *fp;

	fp = fopen("/proc/uptime", "r");
	fscanf(fp, "%lu", uptime);
	fclose(fp);

	snprintf(path, PATH_MAX, "/sys/class/net/%s/statistics/rx_bytes",
		 net_if);
	fp = fopen(path, "r");
	if (fp) {
		fscanf(fp, "%lu", rx);
		fclose(fp);
	}

	snprintf(path, PATH_MAX, "/sys/class/net/%s/statistics/tx_bytes",
		 net_if);
	fp = fopen(path, "r");
	if (fp) {
		fscanf(fp, "%lu", tx);
		fclose(fp);
	}
}

/*
 * Builds some JSON with some system information and sends that to the client
 */
static ssize_t do_response(struct ep_data *conn)
{
	struct websocket_header wh = { .opcode = 0x01, .rsv3 = 0, .rsv2 = 0,
				       .rsv1 = 0, .fin = 1, .masked = 0 };
	const char *json_fmt = "{ \"host\": \"%s\", \"peerip\": \"%s\", "
		"\"uptime\": %lu, \"ifname\": \"%s\", \"rx\": %lu, "
		"\"tx\": %lu, \"ifnames\": [ ";
	char buf[BUF_SIZE];
	char tbuf[BUF_SIZE];
	unsigned long uptime;
	u64 len;
	u64 plen;
	u64 rx_bytes;
	u64 tx_bytes;
	int ext_hdr_len = 0;
	struct ifaddrs *ifaddr;
	struct ifaddrs *ifa;

	get_stats(conn->fdt.conn.net_if, &uptime, &rx_bytes, &tx_bytes);
	len = snprintf(tbuf, sizeof(tbuf), json_fmt, hostname,
		       conn->fdt.conn.peerip, uptime, conn->fdt.conn.net_if,
		       (u64)rx_bytes, (u64)tx_bytes);
	getifaddrs(&ifaddr);
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if (ifa->ifa_addr->sa_family != AF_PACKET)
			break;
		len += snprintf(tbuf + len, sizeof(tbuf) - len,
				"\"%s\", ", ifa->ifa_name);
	}
	freeifaddrs(ifaddr);
	len -= 2;
	tbuf[len] = '\0';
	len += snprintf(tbuf + len, sizeof(tbuf) - len, " ] }");

	/* Set the extra payload length header if required */
	if (len <= PAYLEN_LEN) {
		wh.pay_len = len;
	} else if (len <= UINT16_MAX) {
		wh.pay_len = PAYLEN_LEN16;
		plen = htons((u16)len);
		ext_hdr_len = sizeof(u16);
	} else {
		wh.pay_len = PAYLEN_LEN64;
		plen = htobe64(len);
		ext_hdr_len = sizeof(u64);
	}

	memcpy(buf, &wh, SHORT_HDR_LEN);
	if (len > PAYLEN_LEN)
		memcpy(buf + SHORT_HDR_LEN, &plen, ext_hdr_len);
	memcpy(buf + SHORT_HDR_LEN + ext_hdr_len, tbuf, len);

	return net_write(conn, buf, SHORT_HDR_LEN + ext_hdr_len + len);
}

/*
 * Creates and/or adjusts the clients update timer
 */
static void set_client_timer(struct ep_data *conn)
{
	struct itimerspec its;

	its.it_value.tv_sec = atoi(conn->fdt.conn.msg);
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	if (!conn->fdt.conn.timer) {
		struct epoll_event ev;
		struct ep_data *timer = malloc(sizeof(struct ep_data));

		timer->fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
		timer->type = WS_TIMER;
		timer->fdt.timer.conn = conn;
		conn->fdt.conn.timer = timer;
		ev.events = EPOLLIN | EPOLLET;
		ev.data.ptr = (void *)timer;
		epoll_ctl(epollfd, EPOLL_CTL_ADD, timer->fd, &ev);
	}

	timerfd_settime(conn->fdt.conn.timer->fd, 0, &its, NULL);
	printf("Setting client update frequency to %ld seconds\n",
	       its.it_value.tv_sec);
}

/*
 * The tricky bit here is we need to :-
 *     1) Append the UUID websocket key defined in the spec to the
 *        key sent by the client.
 *     2) Create a SHA1 digest (i.e not the normal hex string) of
 *        the above.
 *     3) Base64 encode the SHA1
 */
static void do_handshake(const char *key, struct ep_data *conn)
{
	SHA_CTX sha1;
	BIO *bmem;
	BIO *b64;
	BUF_MEM *b64p;
	u8 hash[SHA_DIGEST_LENGTH];
	char buf[BUF_SIZE];
	int len;

	SHA1_Init(&sha1);
	SHA1_Update(&sha1, key, strlen(key));
	SHA1_Update(&sha1, WS_KEY, WS_KEY_LEN);
	SHA1_Final(hash, &sha1);

	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_new(BIO_f_base64());
	b64 = BIO_push(b64, bmem);

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b64, hash, SHA_DIGEST_LENGTH);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &b64p);
	b64p->data[b64p->length] = '\0';

	len = snprintf(buf, sizeof(buf),
		       "HTTP/1.1 101 Switching Protocols\r\n"
		       "Upgrade: websocket\r\n"
		       "Connection: Upgrade\r\n"
		       "Sec-WebSocket-Accept: %s\r\n\r\n", b64p->data);
	net_write(conn, buf, len);

	BIO_free_all(b64);
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
	ssize_t processed;
	u64 i;
	u64 plen;
	unsigned char key[MKEY_LEN];
	struct websocket_header *wh;

	wh = (struct websocket_header *)src;
	printf("  FIN        : %d\n", wh->fin);
	printf("  RSV1       : %d\n", wh->rsv1);
	printf("  RSV2       : %d\n", wh->rsv2);
	printf("  RSV3       : %d\n", wh->rsv3);
	printf("  opcode     : 0x%02x (%s)\n", wh->opcode,
	       websocket_opcodes[wh->opcode]);
	printf("  Masked     : %hu\n", wh->masked);
	printf("  pay_len    : %hu\n", wh->pay_len);


	/* Did we get a connection close request? */
	if (wh->opcode == 0x08)
		return -1;

	if (wh->pay_len <= PAYLEN_LEN) {
		moffset = SHORT_HDR_LEN;
		plen = wh->pay_len;
	} else if (wh->pay_len == PAYLEN_LEN16) {
		moffset = sizeof(u16) + SHORT_HDR_LEN;
		plen = ntohs(*(u16 *)(src + SHORT_HDR_LEN));
	} else {
		moffset = sizeof(u64) + SHORT_HDR_LEN;
		plen = be64toh(*(u64 *)(src + SHORT_HDR_LEN));
	}
	printf("  len        : %lu\n", plen);

	/* Decode the payload data */
	memcpy(key, src + moffset, MKEY_LEN);
	for (i = 0; i < plen; i++)
		dest[i] = src[i + moffset + MKEY_LEN] ^ key[i % MKEY_LEN];

	processed = moffset + MKEY_LEN + plen;
	printf("  processed  : %zd\n", processed);

	return processed;
}

static ssize_t read_client_data(struct ep_data *conn)
{
	ssize_t processed;
	ssize_t bytes_read;

	bytes_read = net_read(conn, conn->fdt.conn.rbuf, BUF_SIZE);
	printf("Received data from client (%ld bytes)\n", bytes_read);

	if (bytes_read < SHORT_HDR_LEN)
		return -2;

	memset(conn->fdt.conn.msg, 0, sizeof(conn->fdt.conn.msg));
	processed = decode_frame(conn->fdt.conn.msg, conn->fdt.conn.rbuf);
	if (processed == -1)
		return -1;

	printf("Client data -:\n\n%s\n", conn->fdt.conn.msg);
	if (conn->fdt.conn.msg[0] < '0' || conn->fdt.conn.msg[0] > '9')
		memcpy(conn->fdt.conn.net_if, conn->fdt.conn.msg, 32);
	else
		set_client_timer(conn);

	return processed;
}

static void close_conn(struct ep_data *conn)
{
	printf("Closing connection on %d\n", conn->fd);

	close(conn->fd);
	if (conn->fdt.conn.timer)
		close(conn->fdt.conn.timer->fd);

	free(conn->fdt.conn.timer);
	free(conn);
}

static void handle_conn(struct ep_data *conn)
{
	int err;

	printf("Got request on %d\n", conn->fd);

	err = read_client_data(conn);
	if (err < 0) {
		if (err == -1)
			close_conn(conn);
		return;
	}

	err = do_response(conn);
	if (err == -1)
		 close_conn(conn);
}

static void new_conn(struct ep_data *conn)
{
	char buf[BUF_SIZE + 1];
	char key[64];
	ssize_t bytes_read;

	fprintf(stderr, "new_conn() on fd [%d]\n", conn->fd);

	bytes_read = net_read(conn, &buf, BUF_SIZE);
	buf[bytes_read] = '\0';
	printf("Received from client (%ld bytes) ->\n%s\n", bytes_read, buf);
	if (bytes_read < 1)
		return;

	get_header(key, "Sec-WebSocket-Key:", buf);
	do_handshake(key, conn);
	conn->fdt.conn.connected_ws = true;
}

static void handle_timer(struct ep_data *timer)
{
	u64 tbuf;
	int err;

	read(timer->fd, &tbuf, sizeof(tbuf));
	err = do_response(timer->fdt.timer.conn);
	if (err == -1)
		close_conn(timer);
}

static void do_accept_tls(struct ep_data *conn)
{
	int err;
	SSL **tls = &conn->fdt.conn.tls;

	if (!*tls) {
		*tls = SSL_new(tls_ctx);
		SSL_set_fd(*tls, conn->fd);
	}

	err = SSL_accept(*tls);
	if (err == 1)
		conn->fdt.conn.tls_conn = true;
}

static void do_accept(const struct ep_data *listen_conn)
{
	for (;;) {
		struct epoll_event ev;
		struct ep_data *conn;
		struct sockaddr_storage ss;
		socklen_t addrlen = sizeof(ss);
		int fd;

		fd = accept4(listen_conn->fd, (struct sockaddr *)&ss, &addrlen,
			     SOCK_NONBLOCK);
		if (fd == -1)
			return;

		conn = calloc(1, sizeof(struct ep_data));
		strcpy(conn->fdt.conn.net_if, def_net_if);
		conn->type = listen_conn->type == WSS_LISTEN ?
			     WSS_CONN : WS_CONN;
		conn->fd = fd;
		getnameinfo((struct sockaddr *)&ss, addrlen,
			    conn->fdt.conn.peerip, INET6_ADDRSTRLEN, NULL,
			    0, NI_NUMERICHOST);

		ev.events = EPOLLIN | EPOLLET;
		ev.data.ptr = (void *)conn;
		epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
	}
}

static int do_bind(const char *ip, const char *port)
{
	int lfd;
	int optval = 1;
	int err;
	socklen_t optlen = sizeof(optval);
	struct addrinfo hints;
	struct addrinfo *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

	err = getaddrinfo(ip, port, &hints, &res);
	if (err)
		err_exit("getaddrinfo");

	lfd = socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK,
		     res->ai_protocol);
	if (lfd == -1)
		err_exit("socket");

	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);
	if (res->ai_family == AF_INET6)
		setsockopt(lfd, IPPROTO_IPV6, IPV6_V6ONLY, &optval, optlen);

	err = bind(lfd, res->ai_addr, res->ai_addrlen);
	if (err)
		err_exit("bind");

	err = listen(lfd, 5);
	if (err)
		err_exit("listen");

	freeaddrinfo(res);

	return lfd;
}

int main(int argc, char *argv[])
{
	int n = 0;
	int nfds;
	bool use_tls = false;

	if (argc == 2 && strcmp(argv[1], "tls") == 0)
		use_tls = true;

	epollfd = epoll_create1(0);

	for (; n < (int)(sizeof(listen_on) / sizeof(struct listen_on)); n++) {
		struct epoll_event ev;
		struct ep_data *conn;
		bool tls_port = strcmp(listen_on[n].port, WSS_PORT) == 0 ?
				true : false;

		if (tls_port && !use_tls)
			continue;

		conn = calloc(1, sizeof(struct ep_data));
		conn->type = tls_port ? WSS_LISTEN : WS_LISTEN;
		conn->fd = do_bind(listen_on[n].ip, listen_on[n].port);

		printf("Listening on : %s%s%s:%s\n",
		       (strchr(listen_on[n].ip, ':')) ? "[" : "",
		       listen_on[n].ip,
		       (strchr(listen_on[n].ip, ':')) ? "]" : "",
		       listen_on[n].port);
		ev.events = EPOLLIN;
		ev.data.ptr = (void *)conn;
		epoll_ctl(epollfd, EPOLL_CTL_ADD, conn->fd, &ev);
	}

	/* Don't terminate on -EPIPE */
	signal(SIGPIPE, SIG_IGN);

	/* Get the hostname and network interface */
	memset(hostname, 0, sizeof(hostname));
	gethostname(hostname, HOST_NAME_MAX);
	set_def_net_if();

	if (use_tls)
		init_tls();
	init_seccomp();

epoll_loop:
	nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
	for (n = 0; n < nfds; n++) {
		struct epoll_event *ev = &events[n];
		struct ep_data *ed = ev->data.ptr;

		if (ed->type == WS_LISTEN || ed->type == WSS_LISTEN) {
			do_accept(ed);
		} else if (ev->events & (EPOLLERR | EPOLLHUP)) {
			close_conn(ed);
		} else {
			if (ed->type == WSS_CONN && !ed->fdt.conn.tls_conn)
				do_accept_tls(ed);
			else if (ed->type == WS_TIMER)
				handle_timer(ed);
			else if (!ed->fdt.conn.connected_ws)
				new_conn(ed);
			else
				handle_conn(ed);
		}
	}
	goto epoll_loop;
}
