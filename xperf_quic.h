#pragma once

#include "xperf_kern.h"

struct xperf_quic_data_record {
	unsigned int magic[3];
	unsigned int min_rtt;
	unsigned long long stamp;
	unsigned long long blt_bw;
	unsigned long long snd_cwnd;
};

struct xperf_quic_ack_record {
	unsigned int magic[3];
	unsigned int rtt;
	unsigned long long stamp;
};

// FIXME: Assume little endien

#define XPERF_QUIC_DATA_MAGIC0 XPERF_MAGIC
#define XPERF_QUIC_DATA_MAGIC1 \
	(('q' << 24) | (4 << 16) | sizeof(struct xperf_quic_data_record))
#define XPERF_QUIC_DATA_MAGIC2 (('t' << 16) | ('a' << 8) | ('d' << 0))

#define XPERF_QUIC_ACK_MAGIC0 XPERF_MAGIC
#define XPERF_QUIC_ACK_MAGIC1 \
	(('q' << 24) | (4 << 16) | sizeof(struct xperf_quic_ack_record))
#define XPERF_QUIC_ACK_MAGIC2 (('k' << 16) | ('c' << 8) | ('a' << 0))

#define XPERF_QUIC_DATA_NAME "qdat"
#define XPERF_QUIC_ACK_NAME "qack"
