#define _GNU_SOURCE

#include "xperf_parser.h"
#include "xperf.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define XPERF_RECVBUF_SIZE (1024 * 1024)

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

struct xperf_parser *
xperf_parser_create(const char *dirname,
		    ssize_t (*recv)(void *, void *, size_t), void *recv_ctx)
{
	struct xperf_parser *parser;
	void *buf;
	int dirfd;

	dirfd = dirname ? open(dirname, O_PATH) : AT_FDCWD;
	if (dirname && dirfd == -1) {
		fprintf(stderr, "xperf_parser_create: open(%s): %s\n", dirname,
			strerror(errno));
		return NULL;
	}

	buf = xperf_mmap(XPERF_RECVBUF_SIZE);
	if (!buf)
		goto err;

	parser = malloc(sizeof(*parser));
	if (!parser) {
		fprintf(stderr, "xperf_parser_create: malloc: Out of memory\n");
		goto err_unmap;
	}

	parser->buf = buf;
	parser->dirfd = dirfd;
	parser->recv = recv;
	parser->recv_ctx = recv_ctx;
	parser->off = 0;
	parser->in_use = 0;

	return parser;
err_unmap:
	xperf_munmap(buf, XPERF_RECVBUF_SIZE);

err:
	close(dirfd);
	return NULL;
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

ssize_t xperf_parser_process(struct xperf_parser *parser)
{
	int dirfd;
	size_t off, in_use, processed;
	ssize_t bytes_recv, total_bytes_recv;
	ssize_t (*recv)(void *, void *, size_t);
	void *buf, *rctx;

	dirfd = parser->dirfd;
	buf = parser->buf;
	off = parser->off;
	in_use = parser->in_use;
	recv = parser->recv;
	rctx = parser->recv_ctx;

	total_bytes_recv = 0;
	for (;;) {
		if (off - in_use >= XPERF_RECVBUF_SIZE)
			off -= XPERF_RECVBUF_SIZE;

		bytes_recv =
			(*recv)(rctx, buf + off, XPERF_RECVBUF_SIZE - in_use);
		if (bytes_recv < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			perror("xperf_parser_process: recv");
			break;
		}
		if (bytes_recv <= 0) {
			bytes_recv = 0;
			break;
		}
		total_bytes_recv += bytes_recv;

		off -= in_use;
		bytes_recv += in_use;
		in_use = 0;

		processed = xperf_process_chunks(dirfd, buf + off, bytes_recv);
		off += bytes_recv;
		in_use = bytes_recv - processed;
	}

	parser->off = off;
	parser->in_use = in_use;

	return bytes_recv < 0 ? bytes_recv : total_bytes_recv;
}

void xperf_parser_destory(struct xperf_parser *parser)
{
	xperf_munmap(parser->buf, XPERF_RECVBUF_SIZE);
	close(parser->dirfd);

	free(parser);
}
