#pragma once

struct xperf_chunk {
	unsigned int magic;
	unsigned short size;
	unsigned char name_len;
	char name[0];
} __attribute__((packed));

#define XPERF_MAGIC 0xb76e631

struct xperf_tcp_record {
	unsigned int magic[3];
	unsigned int mss_cache;
	unsigned int snd_cwnd;
	unsigned int srtt_us;
} __attribute__((packed));

// FIXME: Assume little endien
#define XPERF_TCP_MAGIC0 XPERF_MAGIC
#define XPERF_TCP_MAGIC1 \
	(('k' << 24) | (4 << 16) | sizeof(struct xperf_tcp_record))
#define XPERF_TCP_MAGIC2 (('t' << 16) | ('a' << 8) | ('d' << 0))

#define XPERF_TCP_NAME "kdat"

#define TCP_XPERF_ENABLE 32800
#define TCP_XPERF_ADD_CHUNK 32900
