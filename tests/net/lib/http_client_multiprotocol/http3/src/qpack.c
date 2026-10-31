/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* The QPACK field line codec of the HTTP/3 client, which keeps no dynamic
 * table.
 */

#include <string.h>

#include <zephyr/ztest.h>

#include "client_internal.h"

static uint8_t scratch[64];

static void assert_field(const struct h3_field *f, const char *name, const char *value)
{
	zassert_equal(f->name_len, strlen(name), "name length %zu", f->name_len);
	zassert_mem_equal(f->name, name, f->name_len, "name mismatch");
	zassert_equal(f->value_len, strlen(value), "value length %zu", f->value_len);
	zassert_mem_equal(f->value, value, f->value_len, "value mismatch");
}

static void roundtrip(const char *name, const char *value, int expected_len)
{
	uint8_t buf[64];
	struct h3_field f;
	int len;
	int ret;

	len = qpack_encode_field(buf, sizeof(buf), name, value);
	zassert_true(len > 0, "encode failed (%d)", len);
	if (expected_len > 0) {
		zassert_equal(len, expected_len, "encoded %s in %d bytes", name, len);
	}

	ret = qpack_decode_field(buf, len, &f, scratch, sizeof(scratch));
	zassert_equal(ret, len, "decoded %d of %d bytes", ret, len);
	assert_field(&f, name, value);

	/* A truncated line asks for more data. */
	ret = qpack_decode_field(buf, len - 1, &f, scratch, sizeof(scratch));
	zassert_equal(ret, -EAGAIN, "truncated line returned %d", ret);
}

ZTEST(http3_qpack, test_static_indexed)
{
	/* :method GET is static entry 17, one byte. */
	roundtrip(":method", "GET", 1);
	roundtrip(":scheme", "https", 1);
}

ZTEST(http3_qpack, test_static_name_ref)
{
	/* :path has entry 1; the value goes literally. */
	roundtrip(":path", "/dynamic", 2 + 8);
	roundtrip(":authority", "localhost", 2 + 9);
}

ZTEST(http3_qpack, test_literal_name)
{
	/* An 11-byte name overflows the 3-bit length prefix into a second byte. */
	roundtrip("test-header", "abc", 2 + 11 + 1 + 3);
	roundtrip("x-empty", "", 0);
}

ZTEST(http3_qpack, test_huffman_value)
{
	/* :authority with "www.example.com" Huffman-coded (RFC 7541, C.4.1). */
	static const uint8_t line[] = {
		0x50, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
	};
	struct h3_field f;
	int ret;

	ret = qpack_decode_field(line, sizeof(line), &f, scratch, sizeof(scratch));
	zassert_equal(ret, sizeof(line), "decoded %d bytes", ret);
	assert_field(&f, ":authority", "www.example.com");

	/* Too little room to decode into is not a malformed line. */
	ret = qpack_decode_field(line, sizeof(line), &f, scratch, 4);
	zassert_equal(ret, -ENOBUFS, "small scratch returned %d", ret);
}

ZTEST(http3_qpack, test_static_no_value)
{
	/* Indexed :authority (entry 0) has no value in the table. */
	static const uint8_t line[] = {0xc0};
	struct h3_field f;
	int ret;

	ret = qpack_decode_field(line, sizeof(line), &f, scratch, sizeof(scratch));
	zassert_equal(ret, 1, "decoded %d bytes", ret);
	assert_field(&f, ":authority", "");
}

ZTEST(http3_qpack, test_dynamic_refused)
{
	static const uint8_t indexed_dynamic[] = {0x80};
	static const uint8_t name_ref_dynamic[] = {0x40, 0x01, 'x'};
	static const uint8_t post_base[] = {0x10};
	static const uint8_t bad_static[] = {0xff, 0x7f};
	struct h3_field f;

	zassert_equal(qpack_decode_field(indexed_dynamic, 1, &f, scratch, sizeof(scratch)),
		      -EBADMSG);
	zassert_equal(qpack_decode_field(name_ref_dynamic, 3, &f, scratch, sizeof(scratch)),
		      -EBADMSG);
	zassert_equal(qpack_decode_field(post_base, 1, &f, scratch, sizeof(scratch)), -EBADMSG);
	/* Static index 63 + 127 is past the table. */
	zassert_equal(qpack_decode_field(bad_static, 2, &f, scratch, sizeof(scratch)), -EBADMSG);
}

ZTEST(http3_qpack, test_encode_no_room)
{
	uint8_t buf[4];

	zassert_true(qpack_encode_field(buf, sizeof(buf), "test-header", "abc") < 0,
		     "encoded into a short buffer");
}

ZTEST_SUITE(http3_qpack, NULL, NULL, NULL, NULL, NULL);
