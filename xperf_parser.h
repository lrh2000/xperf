#pragma once

#include <stdint.h>
#include <sys/types.h>

struct xperf_parser {
	void *buf;
	int dirfd;

	ssize_t (*recv)(void *ctx, void *buf, size_t len);
	void *recv_ctx;

	size_t off, in_use;
};

struct xperf_parser *
xperf_parser_create(const char *dirname,
		    ssize_t (*recv)(void *, void *, size_t), void *recv_ctx);

ssize_t xperf_parser_process(struct xperf_parser *parser);

void xperf_parser_destory(struct xperf_parser *parser);
