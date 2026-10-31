/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* HTTP/3 framing and QPACK primitives, shared by the HTTP server and client. */

#include <errno.h>
#include <stdint.h>

#include <zephyr/sys/util.h>

#include "headers/http3_internal.h"

static const struct qpack_static_entry qpack_static_table[] = {
	[0] = { .name = ":authority", .value = NULL },
	[1] = { .name = ":path", .value = "/" },
	[2] = { .name = "age", .value = "0" },
	[3] = { .name = "content-disposition", .value = NULL },
	[4] = { .name = "content-length", .value = "0" },
	[5] = { .name = "cookie", .value = NULL },
	[6] = { .name = "date", .value = NULL },
	[7] = { .name = "etag", .value = NULL },
	[8] = { .name = "if-modified-since", .value = NULL },
	[9] = { .name = "if-none-match", .value = NULL },
	[10] = { .name = "last-modified", .value = NULL },
	[11] = { .name = "link", .value = NULL },
	[12] = { .name = "location", .value = NULL },
	[13] = { .name = "referer", .value = NULL },
	[14] = { .name = "set-cookie", .value = NULL },
	[15] = { .name = ":method", .value = "CONNECT" },
	[16] = { .name = ":method", .value = "DELETE" },
	[17] = { .name = ":method", .value = "GET" },
	[18] = { .name = ":method", .value = "HEAD" },
	[19] = { .name = ":method", .value = "OPTIONS" },
	[20] = { .name = ":method", .value = "POST" },
	[21] = { .name = ":method", .value = "PUT" },
	[22] = { .name = ":scheme", .value = "http" },
	[23] = { .name = ":scheme", .value = "https" },
	[24] = { .name = ":status", .value = "103" },
	[25] = { .name = ":status", .value = "200" },
	[26] = { .name = ":status", .value = "304" },
	[27] = { .name = ":status", .value = "404" },
	[28] = { .name = ":status", .value = "503" },
	[29] = { .name = "accept", .value = "*/*" },
	[30] = { .name = "accept", .value = "application/dns-message" },
	[31] = { .name = "accept-encoding", .value = "gzip, deflate, br" },
	[32] = { .name = "accept-ranges", .value = "bytes" },
	[33] = { .name = "access-control-allow-headers", .value = "cache-control" },
	[34] = { .name = "access-control-allow-headers", .value = "content-type" },
	[35] = { .name = "access-control-allow-origin", .value = "*" },
	[36] = { .name = "cache-control", .value = "max-age=0" },
	[37] = { .name = "cache-control", .value = "max-age=2592000" },
	[38] = { .name = "cache-control", .value = "max-age=604800" },
	[39] = { .name = "cache-control", .value = "no-cache" },
	[40] = { .name = "cache-control", .value = "no-store" },
	[41] = { .name = "cache-control", .value = "public, max-age=31536000" },
	[42] = { .name = "content-encoding", .value = "br" },
	[43] = { .name = "content-encoding", .value = "gzip" },
	[44] = { .name = "content-type", .value = "application/dns-message" },
	[45] = { .name = "content-type", .value = "application/javascript" },
	[46] = { .name = "content-type", .value = "application/json" },
	[47] = { .name = "content-type", .value = "application/x-www-form-urlencoded" },
	[48] = { .name = "content-type", .value = "image/gif" },
	[49] = { .name = "content-type", .value = "image/jpeg" },
	[50] = { .name = "content-type", .value = "image/png" },
	[51] = { .name = "content-type", .value = "text/css" },
	[52] = { .name = "content-type", .value = "text/html; charset=utf-8" },
	[53] = { .name = "content-type", .value = "text/plain" },
	[54] = { .name = "content-type", .value = "text/plain;charset=utf-8" },
	[55] = { .name = "range", .value = "bytes=0-" },
	[56] = { .name = "strict-transport-security", .value = "max-age=31536000" },
	[57] = {
		.name = "strict-transport-security",
		.value = "max-age=31536000; includesubdomains",
	},
	[58] = {
		.name = "strict-transport-security",
		.value = "max-age=31536000; includesubdomains; preload",
	},
	[59] = { .name = "vary", .value = "accept-encoding" },
	[60] = { .name = "vary", .value = "origin" },
	[61] = { .name = "x-content-type-options", .value = "nosniff" },
	[62] = { .name = "x-xss-protection", .value = "1; mode=block" },
	[63] = { .name = ":status", .value = "100" },
	[64] = { .name = ":status", .value = "204" },
	[65] = { .name = ":status", .value = "206" },
	[66] = { .name = ":status", .value = "302" },
	[67] = { .name = ":status", .value = "400" },
	[68] = { .name = ":status", .value = "403" },
	[69] = { .name = ":status", .value = "421" },
	[70] = { .name = ":status", .value = "425" },
	[71] = { .name = ":status", .value = "500" },
	[72] = { .name = "accept-language", .value = NULL },
	[73] = { .name = "access-control-allow-credentials", .value = "FALSE" },
	[74] = { .name = "access-control-allow-credentials", .value = "TRUE" },
	[75] = { .name = "access-control-allow-headers", .value = "*" },
	[76] = { .name = "access-control-allow-methods", .value = "get" },
	[77] = { .name = "access-control-allow-methods", .value = "get, post, options" },
	[78] = { .name = "access-control-allow-methods", .value = "options" },
	[79] = { .name = "access-control-expose-headers", .value = "content-length" },
	[80] = { .name = "access-control-request-headers", .value = "content-type" },
	[81] = { .name = "access-control-request-method", .value = "get" },
	[82] = { .name = "access-control-request-method", .value = "post" },
	[83] = { .name = "alt-svc", .value = "clear" },
	[84] = { .name = "authorization", .value = NULL },
	[85] = {
		.name = "content-security-policy",
		.value = "script-src 'none'; object-src 'none'; base-uri 'none'",
	},
	[86] = { .name = "early-data", .value = "1" },
	[87] = { .name = "expect-ct", .value = NULL },
	[88] = { .name = "forwarded", .value = NULL },
	[89] = { .name = "if-range", .value = NULL },
	[90] = { .name = "origin", .value = NULL },
	[91] = { .name = "purpose", .value = "prefetch" },
	[92] = { .name = "server", .value = NULL },
	[93] = { .name = "timing-allow-origin", .value = "*" },
	[94] = { .name = "upgrade-insecure-requests", .value = "1" },
	[95] = { .name = "user-agent", .value = NULL },
	[96] = { .name = "x-forwarded-for", .value = NULL },
	[97] = { .name = "x-frame-options", .value = "deny" },
	[98] = { .name = "x-frame-options", .value = "sameorigin" },
};

BUILD_ASSERT(ARRAY_SIZE(qpack_static_table) == QPACK_STATIC_TABLE_LEN);

/**
 * Parse a QUIC variable-length integer (RFC 9000 Section 16).
 *
 * @param buf    Input buffer.
 * @param buflen Available bytes in buffer.
 * @param value  Output: parsed integer value.
 *
 * @return Number of bytes consumed, or -EINVAL on error.
 */
int http3_varint_decode(const uint8_t *buf, size_t buflen, uint64_t *value)
{
	uint8_t prefix;
	int len;

	if (buflen == 0) {
		return -EINVAL;
	}

	prefix = buf[0] >> 6;
	len = 1 << prefix;

	if ((size_t)len > buflen) {
		return -EINVAL;
	}

	*value = buf[0] & (0x3f);

	for (int i = 1; i < len; i++) {
		*value = (*value << 8) | buf[i];
	}

	return len;
}

/**
 * Encode a QUIC variable-length integer (RFC 9000 Section 16).
 *
 * @param buf    Output buffer.
 * @param buflen Available space.
 * @param value  Value to encode.
 *
 * @return Number of bytes written, or <0 on error.
 */
int http3_varint_encode(uint8_t *buf, size_t buflen, uint64_t value)
{
	if (value <= 0x3f) {
		if (buflen < 1) {
			return -ENOSPC;
		}

		buf[0] = (uint8_t)value;
		return 1;
	}

	if (value <= 0x3fff) {
		if (buflen < 2) {
			return -ENOSPC;
		}

		buf[0] = (uint8_t)((value >> 8) | 0x40);
		buf[1] = (uint8_t)(value & 0xff);
		return 2;
	}

	if (value <= 0x3fffffff) {
		if (buflen < 4) {
			return -ENOSPC;
		}

		buf[0] = (uint8_t)((value >> 24) | 0x80);
		buf[1] = (uint8_t)((value >> 16) & 0xff);
		buf[2] = (uint8_t)((value >> 8) & 0xff);
		buf[3] = (uint8_t)(value & 0xff);
		return 4;
	}

	if (buflen < 8) {
		return -ENOSPC;
	}

	buf[0] = (uint8_t)((value >> 56) | 0xc0);
	buf[1] = (uint8_t)((value >> 48) & 0xff);
	buf[2] = (uint8_t)((value >> 40) & 0xff);
	buf[3] = (uint8_t)((value >> 32) & 0xff);
	buf[4] = (uint8_t)((value >> 24) & 0xff);
	buf[5] = (uint8_t)((value >> 16) & 0xff);
	buf[6] = (uint8_t)((value >> 8) & 0xff);
	buf[7] = (uint8_t)(value & 0xff);
	return 8;
}

/**
 * Parse an HTTP/3 frame header (type + length).
 *
 * @param buf       Input buffer.
 * @param buflen    Available bytes.
 * @param type      Output: frame type.
 * @param frame_len Output: frame payload length.
 *
 * @return Number of bytes consumed by the frame header, or <0 on error.
 */
int http3_frame_header_parse(const uint8_t *buf, size_t buflen, uint64_t *type, uint64_t *frame_len)
{
	int consumed = 0;
	int ret;

	ret = http3_varint_decode(buf, buflen, type);
	if (ret < 0) {
		return ret;
	}

	consumed += ret;

	ret = http3_varint_decode(buf + consumed, buflen - consumed, frame_len);
	if (ret < 0) {
		return ret;
	}

	consumed += ret;

	return consumed;
}

/**
 * Decode a QPACK integer with the given prefix length.
 *
 * @param buf       Input buffer.
 * @param buflen    Available bytes.
 * @param prefix_n  Number of prefix bits (e.g. 6, 4, 3).
 * @param value     Output: decoded integer.
 *
 * @return Number of bytes consumed, or <0 on error.
 */
int qpack_decode_int(const uint8_t *buf, size_t buflen, int prefix_n, uint64_t *value)
{
	uint8_t max_first;
	int consumed;
	uint64_t shift;
	uint8_t b;

	if (buflen == 0) {
		return -EINVAL;
	}

	max_first = (1 << prefix_n) - 1;
	*value = buf[0] & max_first;
	consumed = 1;

	if (*value < max_first) {
		return consumed;
	}

	/* Multi-byte integer */
	shift = 0;

	do {
		if (consumed >= (int)buflen) {
			return -EINVAL;
		}

		/* Nine continuation bytes carry 63 bits, which cannot overflow the
		 * accumulator. Anything longer is too large to be a valid length or
		 * index, so reject it rather than let the value wrap.
		 */
		if (shift > 56U) {
			return -EBADMSG;
		}

		b = buf[consumed];
		*value += (uint64_t)(b & 0x7f) << shift;
		shift += 7;
		consumed++;
	} while (b & 0x80);

	return consumed;
}

/**
 * Encode a QPACK integer with the given prefix.
 *
 * @param buf       Output buffer.
 * @param buflen    Available space.
 * @param prefix_n  Number of prefix bits.
 * @param prefix    Prefix byte (high bits already set).
 * @param value     Value to encode.
 *
 * @return Number of bytes written, or <0 on error.
 */
int qpack_encode_int(uint8_t *buf, size_t buflen, int prefix_n, uint8_t prefix, uint64_t value)
{
	uint8_t max_first;
	int pos = 0;

	if (buflen == 0) {
		return -ENOSPC;
	}

	max_first = (1 << prefix_n) - 1;

	if (value < max_first) {
		buf[0] = prefix | (uint8_t)value;
		return 1;
	}

	buf[pos++] = prefix | max_first;
	value -= max_first;

	while (value >= 128) {
		if (pos >= (int)buflen) {
			return -ENOSPC;
		}

		buf[pos++] = (uint8_t)(0x80 | (value & 0x7f));
		value >>= 7;
	}

	if (pos >= (int)buflen) {
		return -ENOSPC;
	}

	buf[pos++] = (uint8_t)value;

	return pos;
}

int qpack_static_entry_get(uint64_t index, const struct qpack_static_entry **entry)
{
	if (index >= ARRAY_SIZE(qpack_static_table)) {
		return -ENOENT;
	}

	*entry = &qpack_static_table[index];

	if ((*entry)->name == NULL) {
		return -ENOENT;
	}

	return 0;
}
