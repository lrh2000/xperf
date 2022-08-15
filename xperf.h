#pragma once

#include "xperf_kern.h"

#define _GNU_SOURCE
#include <string.h>

#define XPERF_KEY \
	"5a78c5a969e7144d2524d9505c96b2326009be881aa7be4b9599f798e22271bcd3c08fd38e00e23b8046c45330e8bd5068b67ef9bd5259a8f4334e2ca409f6a7"
#define XPERF_KEY_LEN 128

#define XPERF_DEFAULT_PORT 9999

#define STRINGIFY(x) #x
#define TO_STRING(x) STRINGIFY(x)

static inline size_t xperf_chunk_get_data_len(struct xperf_chunk *chunk)
{
	return chunk->size - sizeof(*chunk) - chunk->name_len - 1;
}

static inline void *xperf_chunk_get_data_ptr(struct xperf_chunk *chunk)
{
	return (void *)chunk + sizeof(*chunk) + chunk->name_len + 1;
}

static inline struct xperf_chunk *
xperf_chunk_start_write(const char *name, void **pbuf, size_t *psize)
{
	struct xperf_chunk *chunk;
	size_t size, name_len;

	size = *psize;
	if (size <= sizeof(struct xperf_chunk))
		return NULL;

	size -= sizeof(struct xperf_chunk);
	name_len = strlen(name);
	if (name_len >= 127 || name_len >= size)
		return NULL;

	chunk = *pbuf;
	chunk->name_len = name_len;
	chunk->size = sizeof(*chunk) + name_len + 1;

	memcpy(chunk->name, name, name_len + 1);
	size -= name_len + 1;

	*psize = size;
	*pbuf += sizeof(*chunk) + name_len + 1;

	return chunk;
}

static inline void xperf_chunk_end_write(struct xperf_chunk *chunk, size_t size)
{
	size_t new_size;

	new_size = chunk->size + size;
	if (new_size < size || new_size > 65535)
		return;

	chunk->size = new_size;
	chunk->magic = XPERF_MAGIC;
}

static inline struct xperf_chunk *xperf_chunk_lookup(void **pbuf, size_t *psize)
{
	const int magic = XPERF_MAGIC;

	void *buf, *tgt;
	size_t size;
	struct xperf_chunk *chunk;

	buf = *pbuf;
	size = *psize;

	tgt = memmem(buf, size, &magic, sizeof(magic));
	if (tgt == NULL) {
		*pbuf += size;
		*psize = 0;
		return NULL;
	}

	size -= tgt - buf;

	chunk = NULL;
	if (size >= sizeof(struct xperf_chunk))
		chunk = tgt;
	if (chunk && size < chunk->size)
		chunk = NULL;

	if (chunk) {
		tgt += chunk->size;
		size -= chunk->size;
	}

	*pbuf = tgt;
	*psize = size;

	return chunk;
}
