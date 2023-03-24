#include "xperf.h"
#include "xperf_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>

static int xperf_init(int port)
{
	int fd, cfd;
	struct sockaddr_in addr;
	struct sockaddr caddr;
	socklen_t addrlen;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("xperf_init: socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("xperf_init: bind");
		close(fd);
		return -1;
	}

	if (listen(fd, 0) < 0) {
		perror("xperf_init: listen");
		close(fd);
		return -1;
	}

	addrlen = sizeof(caddr);
	cfd = accept(fd, &caddr, &addrlen);
	if (cfd < 0) {
		perror("xperf_init: accept");
		close(fd);
		return -1;
	}

	close(fd);
	return cfd;
}

static int xperf_auth(int fd)
{
	char key[XPERF_KEY_LEN];

	if (recv(fd, key, sizeof(key), MSG_WAITALL) < 0) {
		perror("xperf_auth: recv");
		return -1;
	}

	if (memcmp(key, XPERF_KEY, XPERF_KEY_LEN) != 0) {
		fprintf(stderr, "xperf_auth: Invalid key\n");
		return -1;
	}

	return 0;
}

static int xperf_enable(int fd)
{
	static const int one = 1;

	if (setsockopt(fd, SOL_TCP, TCP_XPERF_ENABLE, &one, sizeof(one)) < 0) {
		perror("xperf_enable: setsockopt");
		return -1;
	}

	return 0;
}

#define PAGE_SIZE 4096

static void *xperf_mmap(size_t nr_pages)
{
	void *addr, *map_addr;
	size_t i;
	int fd;

	if (!nr_pages)
		return NULL;

	fd = memfd_create("sendbuf", 0);
	if (fd < 0) {
		perror("xperf_mmap: memfd_create");
		return NULL;
	}

	addr = NULL;
	if (ftruncate(fd, PAGE_SIZE) < 0) {
		perror("xperf_mmap: ftruncate");
		goto out;
	}

	map_addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			0);
	if (map_addr == MAP_FAILED) {
		perror("xperf_mmap: mmap(write)");
		goto out;
	}

	memset(map_addr, 0x7f, PAGE_SIZE);

	munmap(map_addr, PAGE_SIZE);

	map_addr =
		mmap(NULL, PAGE_SIZE * nr_pages, PROT_READ, MAP_SHARED, fd, 0);
	if (map_addr == MAP_FAILED) {
		perror("xperf_mmap: mmap(0)");
		goto out;
	}

	addr = map_addr;
	for (i = 1; i < nr_pages; ++i) {
		map_addr = mmap(addr + PAGE_SIZE * i, PAGE_SIZE, PROT_READ,
				MAP_SHARED | MAP_FIXED, fd, 0);
		if (map_addr == MAP_FAILED) {
			fprintf(stderr, "xperf_mmap: mmap(%lu): %s", i,
				strerror(errno));
			goto out_unmap;
		}
	}

out:
	close(fd);
	return addr;

out_unmap:
	munmap(addr, PAGE_SIZE * nr_pages);

	addr = NULL;
	goto out;
}

static void xperf_munmap(void *addr, size_t nr_pages)
{
	munmap(addr, nr_pages * PAGE_SIZE);
}

static int xperf_run(int fd)
{
	void *data;

	data = xperf_mmap(256);
	if (!data)
		return -1;

	fprintf(stderr, "xperf_run: Running...\n");
	while (send(fd, data, 256 * PAGE_SIZE, 0) > 0)
		;
	fprintf(stderr, "xperf_run: Exiting...\n");

	xperf_munmap(data, 256);

	return 0;
}

static ssize_t xperf_emit_chunk(void *ctx, const void *buf, size_t len)
{
	if (setsockopt((unsigned long)ctx, SOL_TCP, TCP_XPERF_ADD_CHUNK, buf,
		       len) < 0) {
		fprintf(stderr, "xperf_emit_chunk: setsockopt: %s",
			strerror(errno));
		return len;
	}

	return len;
}

static void *xperf_monitor_main(void *data)
{
	struct xperf_monitor *monitor;

	monitor = data;

	xperf_monitor_init(monitor);

	while (xperf_monitor_process(monitor) > 0)
		;

	xperf_monitor_destory(monitor);

	return NULL;
}

static int xperf_monitor_start(struct xperf_monitor *monitor)
{
	pthread_t thread_id;

	if (pthread_create(&thread_id, NULL, &xperf_monitor_main, monitor) != 0)
		return -1;

	pthread_detach(thread_id);

	return 0;
}

static void xperf_usage(const char *progname)
{
	fprintf(stderr,
		// clang-format off
		"Usage: %s [-p PORT] [FILES...]\n"
		"Options:\n"
		"        -p PORT         TCP port that the server listens at\n"
		"                        (Default: " TO_STRING(XPERF_DEFAULT_PORT) ")\n"
		"        FILES...        Files that the server sends to the client\n",
		// clang-format on
		progname);
}

extern char *optarg;
extern int optind;

static int xperf_getopt(int argc, char **argv, int *port)
{
	int opt;
	char *endptr;

	*port = XPERF_DEFAULT_PORT;

	while ((opt = getopt(argc, argv, "p:")) != -1) {
		switch (opt) {
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

	return 0;
}

int main(int argc, char **argv)
{
	int port, fd;
	struct xperf_monitor *monitor;

	if (xperf_getopt(argc, argv, &port) < 0)
		return 1;

	fd = xperf_init(port);
	if (fd < 0)
		return 2;

	if (xperf_auth(fd) < 0)
		return 3;

	monitor = xperf_monitor_create(0, (const char **)&argv[optind],
				       argc - optind, &xperf_emit_chunk,
				       (void *)(unsigned long)fd, NULL);
	if (!monitor)
		return 4;

	if (xperf_enable(fd) < 0)
		return 5;

	if (xperf_monitor_start(monitor) < 0)
		return 6;

	return xperf_run(fd);
}
