#include "xperf.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

static void *xperf_mmap(size_t size)
{
	int fd;
	void *addr, *addr2;

	fd = memfd_create("recvbuf", 0);
	if (fd < 0) {
		perror("xperf_mmap: memfd_create");
		return NULL;
	}

	if (ftruncate(fd, size) < 0) {
		perror("xperf_mmap: ftruncate");
		close(fd);
		return NULL;
	}

	addr = mmap(NULL, size * 2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		perror("xperf_mmap: mmap-1");
		close(fd);
		return NULL;
	}

	addr2 = mmap(addr + size, size, PROT_READ | PROT_WRITE,
		     MAP_SHARED | MAP_FIXED, fd, 0);
	if (addr2 == MAP_FAILED) {
		perror("xperf_mmap: mmap-2");
		munmap(addr, size * 2);
		close(fd);
		return NULL;
	}

	close(fd);
	return addr;
}

static void xperf_munmap(void *addr, size_t size)
{
	munmap(addr, size * 2);
}

static int xperf_process_chunk(int dirfd, struct xperf_chunk *chunk)
{
	int fd;
	void *data;
	size_t len;
	ssize_t written;

	fprintf(stderr,
		"xperf_process_chunk: chunk recv, name %s, payload %ld bytes\n",
		chunk->name, xperf_chunk_get_data_len(chunk));

	fd = openat(dirfd, chunk->name, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (fd < 0) {
		fprintf(stderr, "xperf_process_chunk: open(%s): %s\n",
			chunk->name, strerror(errno));
		return -1;
	}

	data = xperf_chunk_get_data_ptr(chunk);
	len = xperf_chunk_get_data_len(chunk);

	while (len != 0) {
		written = write(fd, data, len);
		if (written <= 0) {
			fprintf(stderr, "xperf_process_chunk: write(%s): %s\n",
				chunk->name, strerror(errno));
			close(fd);
			return -1;
		}

		len -= written;
		data += written;
	}

	close(fd);
	return 0;
}

static size_t xperf_process_chunks(int dirfd, void *buf, size_t len)
{
	struct xperf_chunk *chunk;
	size_t orig_len;

	orig_len = len;
	while ((chunk = xperf_chunk_lookup(&buf, &len)))
		xperf_process_chunk(dirfd, chunk);

	return orig_len - len;
}

#define XPERF_RECVBUF_SIZE (1024 * 1024)

static int xperf_run(int fd, int dirfd)
{
	void *buf;
	size_t off, in_use, processed;
	ssize_t bytes_recv;

	buf = xperf_mmap(XPERF_RECVBUF_SIZE);
	if (!buf)
		return -1;

	off = in_use = 0;
	for (;;) {
		if (off - in_use >= XPERF_RECVBUF_SIZE)
			off -= XPERF_RECVBUF_SIZE;

		bytes_recv =
			recv(fd, buf + off, XPERF_RECVBUF_SIZE - in_use, 0);
		if (bytes_recv <= 0) {
			fprintf(stderr, "xperf_run: recv: %s\n",
				bytes_recv == 0 ? "End of stream" :
						  strerror(errno));
			break;
		}

		off -= in_use;
		bytes_recv += in_use;
		in_use = 0;

		processed = xperf_process_chunks(dirfd, buf + off, bytes_recv);
		off += bytes_recv;
		in_use = bytes_recv - processed;
	}

	xperf_munmap(buf, XPERF_RECVBUF_SIZE);
	return 0;
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

static int xperf_getopt(int argc, char **argv, int *dir, int *port,
			const char **server_addr)
{
	int opt;
	char *endptr;

	*port = XPERF_DEFAULT_PORT;
	*dir = AT_FDCWD;

	while ((opt = getopt(argc, argv, "d:p:")) != -1) {
		switch (opt) {
		case 'd':
			*dir = open(optarg, O_PATH);
			if (*dir >= 0)
				break;

			fprintf(stderr, "xperf_getopt: open(%s): %s\n", optarg,
				strerror(errno));
			return -1;
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
	const char *server_addr;
	int dir, port, fd;
	int retval;

	retval = 1;
	if (xperf_getopt(argc, argv, &dir, &port, &server_addr) < 0)
		goto out_dir;

	retval = 2;
	fd = xperf_connect(server_addr, port);
	if (fd < 0)
		goto out_dir;

	retval = 3;
	if (xperf_send_key(fd) < 0)
		goto out;

	retval = xperf_run(fd, dir);

out:
	close(fd);

out_dir:
	if (dir != AT_FDCWD)
		close(dir);

	return retval;
}
