#define _GNU_SOURCE

#include "xperf_monitor.h"
#include "xperf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#define XPERF_SENDBUF_SIZE 4096

struct xperf_monitor *
xperf_monitor_create(int flags, const char *const *filenames, int file_cnt,
		     ssize_t (*send)(void *, const void *, size_t),
		     void *send_ctx, void *(*alloc)(size_t))
{
	struct xperf_monitor *monitor;
	struct xperf_monitor_file *files;
	int i, wfd;

	if (file_cnt > 10) {
		fprintf(stderr, "xperf_monitor_create: Too many files\n");
		goto out;
	}

	wfd = inotify_init1(flags);
	if (wfd < 0) {
		perror("xperf_monitor_create: inotify_init1");
		goto out;
	}

	monitor = malloc(sizeof(struct xperf_monitor) +
			 sizeof(struct xperf_monitor_file) * file_cnt);
	if (!monitor) {
		fprintf(stderr,
			"xperf_monitor_create: malloc-1: Out of memory\n");
		goto out_close;
	}

	if (alloc) {
		monitor->alloc = alloc;
		monitor->reusable_buf = NULL;
	} else {
		monitor->alloc = NULL;
		monitor->reusable_buf = malloc(XPERF_SENDBUF_SIZE);
		if (!monitor) {
			fprintf(stderr,
				"xperf_monitor_create: malloc-2: Out of memory\n");
			goto out_free;
		}
	}

	files = monitor->files;
	for (i = 0; i < file_cnt; ++i) {
		files[i].wd = inotify_add_watch(wfd, filenames[i], IN_MODIFY);
		if (files[i].wd < 0) {
			fprintf(stderr,
				"xperf_monitor_create: inotify_add_watch(%s): %s\n",
				filenames[i], strerror(errno));
			goto out_for;
		}

		files[i].fd = open(filenames[i], O_RDONLY);
		if (files[i].fd < 0) {
			fprintf(stderr, "xperf_monitor_create: open(%s): %s\n",
				filenames[i], strerror(errno));
			goto out_for;
		}

		files[i].name = basename(filenames[i]);
	}

	monitor->watch_fd = wfd;
	monitor->file_cnt = file_cnt;

	monitor->send = send;
	monitor->send_ctx = send_ctx;

	return monitor;

out_for:
	for (--i; i >= 0; --i)
		close(files[i].fd);

	free(monitor->reusable_buf);
out_free:
	free(monitor);
out_close:
	close(wfd);
out:
	return NULL;
}

static ssize_t xperf_monitor_process_file_once(struct xperf_monitor *monitor,
					       struct xperf_monitor_file *file)
{
	size_t size;
	ssize_t size_filled;
	void *buf;
	struct xperf_chunk *chunk;

	if (monitor->reusable_buf) {
		buf = monitor->reusable_buf;
		size = XPERF_SENDBUF_SIZE;
	} else {
		buf = (*monitor->alloc)(XPERF_SENDBUF_SIZE);
		size = XPERF_SENDBUF_SIZE;
		if (!buf) {
			fprintf(stderr,
				"xperf_monitor_process_file_once: alloc: Out of memory\n");
			return -1;
		}
	}

	chunk = xperf_chunk_start_write(file->name, &buf, &size);
	assert(chunk != NULL);

	size_filled = read(file->fd, buf, size);
	if (size_filled < 0) {
		fprintf(stderr,
			"xperf_monitor_process_file_once(%s): read: %s\n",
			file->name, strerror(errno));
		return size_filled;
	}
	if (size_filled <= 0) {
		return size_filled;
	}

	size_filled = xperf_chunk_end_write(chunk, size_filled);

	if ((*monitor->send)(monitor->send_ctx, chunk, size_filled) < 0) {
		perror("xperf_monitor_process_file_once: send");
		return size_filled;
	}

	fprintf(stderr,
		"xperf_monitor_process_file_once: chunk sent, name %s, payload %ld bytes\n",
		chunk->name, xperf_chunk_get_data_len(chunk));

	return size_filled;
}

static ssize_t xperf_monitor_process_file(struct xperf_monitor *monitor,
					  struct xperf_monitor_file *file)
{
	ssize_t retval;

	do
		retval = xperf_monitor_process_file_once(monitor, file);
	while (retval > 0);

	return retval;
}

int xperf_monitor_init(struct xperf_monitor *monitor)
{
	unsigned int i;
	int fail = 0;

	for (i = 0; i < monitor->file_cnt; ++i)
		fail += xperf_monitor_process_file(monitor,
						   &monitor->files[i]) < 0;

	return -fail;
}

static ssize_t xperf_monitor_process_event(struct xperf_monitor *monitor,
					   const struct inotify_event *event)
{
	struct xperf_monitor_file *files;
	unsigned int i;

	if (!(event->mask & IN_MODIFY))
		return 0;

	files = monitor->files;
	for (i = 0; i < monitor->file_cnt; ++i)
		if (monitor->files[i].wd == event->wd)
			break;

	if (i == monitor->file_cnt) {
		fprintf(stderr, "xperf_monitor_process_event: No such file\n");
		return -1;
	}

	return xperf_monitor_process_file(monitor, &files[i]);
}

static void xperf_monitor_process_events(struct xperf_monitor *monitor,
					 const char *buf, ssize_t len)
{
	const struct inotify_event *event;
	const char *buf_end;

	for (buf_end = buf + len; buf < buf_end;
	     buf += sizeof(*event) + event->len) {
		event = (const struct inotify_event *)buf;

		xperf_monitor_process_event(monitor, event);
	}
}

ssize_t xperf_monitor_process(struct xperf_monitor *monitor)
{
	int wfd;
	char buf[256];
	ssize_t len, total_len;

	wfd = monitor->watch_fd;
	total_len = 0;
	for (;;) {
		len = read(wfd, buf, sizeof(buf));
		if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			perror("xperf_monitor_run: read");
			break;
		}
		if (len <= 0) {
			len = 0;
			break;
		}
		total_len += len;

		xperf_monitor_process_events(monitor, buf, len);
	}

	return len < 0 ? len : total_len;
}

void xperf_monitor_destory(struct xperf_monitor *monitor)
{
	int i, cnt;

	cnt = monitor->file_cnt;
	for (i = 0; i < cnt; ++i)
		close(monitor->files[i].fd);

	close(monitor->watch_fd);
	free(monitor->reusable_buf);

	free(monitor);
}
