#include "xperf.h"
#include "xperf_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static int xperf_connect(const char *ip, int port)
{
	int fd, retval;
	struct sockaddr_in addr;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("xperf_connect: socket");
		return -1;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	retval = inet_pton(AF_INET, ip, &addr.sin_addr);
	if (retval <= 0) {
		fprintf(stderr, "xperf_connect: inet_pton: %s\n",
			retval == 0 ? "Not in presentation format" :
				      strerror(errno));
		close(fd);
		return -1;
	}

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("xperf_connect: connect");
		close(fd);
		return -1;
	}

	return fd;
}

static int xperf_send_key(int fd)
{
	const char *key;
	size_t key_len;
	ssize_t bytes_sent;

	key = XPERF_KEY;
	key_len = XPERF_KEY_LEN;
	while (key_len != 0) {
		bytes_sent = send(fd, key, key_len, 0);
		if (bytes_sent <= 0) {
			fprintf(stderr, "xperf_send_key: send: %s\n",
				bytes_sent == 0 ? "End of stream" :
						  strerror(errno));
			return -1;
		}

		key += bytes_sent;
		key_len -= bytes_sent;
	}

	return 0;
}

static ssize_t xperf_recv(void *ctx, void *buf, size_t len)
{
	return recv((unsigned long)ctx, buf, len, 0);
}

static int xperf_run(int sock_fd, const char *dirname)
{
	struct xperf_parser *parser;
	int retval;

	parser = xperf_parser_create(dirname, &xperf_recv,
				     (void *)(unsigned long)sock_fd);
	if (!parser)
		return -1;

	while ((retval = xperf_parser_process(parser)) > 0)
		;

	xperf_parser_destory(parser);

	return retval;
}

static void xperf_usage(const char *progname)
{
	fprintf(stderr,
		// clang-format off
		"Usage: %s [-d DIR] [-p PORT] SERVER-ADDR\n"
		"Options:\n"
		"        -d DIR          Directory to store server-side files\n"
		"                        (Default: Current woring directory)\n"
		"        -p PORT         Server's TCP port\n"
		"                        (Default: " TO_STRING(XPERF_DEFAULT_PORT) ")\n"
		"        SERVER-ADDR     Server's IPv4 address\n",
		// clang-format on
		progname);
}

extern char *optarg;
extern int optind;

static int xperf_getopt(int argc, char **argv, const char **dirname, int *port,
			const char **server_addr)
{
	int opt;
	char *endptr;

	*port = XPERF_DEFAULT_PORT;
	*dirname = NULL;

	while ((opt = getopt(argc, argv, "d:p:")) != -1) {
		switch (opt) {
		case 'd':
			*dirname = optarg;
			break;
		case 'p':
			*port = strtol(optarg, &endptr, 0);
			if (*optarg && !*endptr)
				break;

			fprintf(stderr,
				"xperf_getopt: strtol(%s): Invalid number\n",
				optarg);
			return -1;
		default:
			xperf_usage(argv[0]);
			return -1;
		}
	}

	if (optind != argc - 1) {
		xperf_usage(argv[0]);
		return -1;
	}

	*server_addr = argv[optind];
	return 0;
}

int main(int argc, char **argv)
{
	const char *server_addr, *dirname;
	int port, fd;
	int retval;

	if (xperf_getopt(argc, argv, &dirname, &port, &server_addr) < 0)
		return 1;

	fd = xperf_connect(server_addr, port);
	if (fd < 0)
		return 2;

	if (xperf_send_key(fd) < 0)
		retval = 3;
	else
		retval = xperf_run(fd, dirname);

	close(fd);

	return retval;
}
