#pragma once

#include <stdint.h>
#include <sys/types.h>

struct xperf_monitor_file {
	const char *name;
	int fd;
	int wd;
};

struct xperf_monitor {
	int watch_fd;

	ssize_t (*send)(void *ctx, const void *buf, size_t len);
	void *send_ctx;

	void *(*alloc)(size_t len);
	void *reusable_buf;

	unsigned int file_cnt;
	struct xperf_monitor_file files[];
};

struct xperf_monitor *
xperf_monitor_create(int flags, const char *const *filenames, int file_cnt,
		     ssize_t (*send)(void *, const void *, size_t),
		     void *send_ctx, void *(*alloc)(size_t));

int xperf_monitor_init(struct xperf_monitor *monitor);

ssize_t xperf_monitor_process(struct xperf_monitor *monitor);

void xperf_monitor_destory(struct xperf_monitor *monitor);
