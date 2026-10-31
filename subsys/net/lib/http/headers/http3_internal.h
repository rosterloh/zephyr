/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* HTTP/3 and QPACK wire format, shared by the HTTP server and client. */

#ifndef HTTP3_INTERNAL_H_
#define HTTP3_INTERNAL_H_

#include <stddef.h>
#include <stdint.h>

/* HTTP/3 frame types (RFC 9114 Section 7.2) */
#define H3_FRAME_DATA         0x00
#define H3_FRAME_HEADERS      0x01
#define H3_FRAME_CANCEL_PUSH  0x03
#define H3_FRAME_SETTINGS     0x04
#define H3_FRAME_PUSH_PROMISE 0x05
#define H3_FRAME_GOAWAY       0x07
#define H3_FRAME_MAX_PUSH_ID  0x0d

/* HTTP/3 Settings identifiers (RFC 9114 Section 7.2.4.1) */
#define H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY 0x01
#define H3_SETTINGS_MAX_FIELD_SECTION_SIZE   0x06
#define H3_SETTINGS_QPACK_BLOCKED_STREAMS    0x07

/* HTTP/3 unidirectional stream types (RFC 9114 Section 6.2) */
#define H3_UNI_STREAM_CONTROL       0x00
#define H3_UNI_STREAM_PUSH          0x01
#define H3_UNI_STREAM_QPACK_ENCODER 0x02
#define H3_UNI_STREAM_QPACK_DECODER 0x03

/* HTTP/3 error codes (RFC 9114 Section 8.1) */
#define H3_NO_ERROR               0x0100
#define H3_GENERAL_PROTOCOL_ERROR 0x0101
#define H3_INTERNAL_ERROR         0x0102
#define H3_STREAM_CREATION_ERROR  0x0103
#define H3_CLOSED_CRITICAL_STREAM 0x0104
#define H3_FRAME_UNEXPECTED       0x0105
#define H3_FRAME_ERROR            0x0106
#define H3_EXCESSIVE_LOAD         0x0107
#define H3_ID_ERROR               0x0108
#define H3_SETTINGS_ERROR         0x0109
#define H3_MISSING_SETTINGS       0x010a
#define H3_REQUEST_REJECTED       0x010b
#define H3_REQUEST_CANCELLED      0x010c
#define H3_REQUEST_INCOMPLETE     0x010d
#define H3_MESSAGE_ERROR          0x010e
#define H3_CONNECT_ERROR          0x010f
#define H3_VERSION_FALLBACK       0x0110

/* QPACK error codes (RFC 9204 Section 6) */
#define QPACK_DECOMPRESSION_FAILED 0x0200
#define QPACK_ENCODER_STREAM_ERROR 0x0201
#define QPACK_DECODER_STREAM_ERROR 0x0202

/* QPACK static table indices (RFC 9204 Appendix A) */
#define QPACK_STATIC_AUTHORITY         0
#define QPACK_STATIC_PATH_SLASH        1
#define QPACK_STATIC_METHOD_CONNECT    15
#define QPACK_STATIC_METHOD_DELETE     16
#define QPACK_STATIC_METHOD_GET        17
#define QPACK_STATIC_METHOD_HEAD       18
#define QPACK_STATIC_METHOD_OPTIONS    19
#define QPACK_STATIC_METHOD_POST       20
#define QPACK_STATIC_METHOD_PUT        21
#define QPACK_STATIC_SCHEME_HTTP       22
#define QPACK_STATIC_SCHEME_HTTPS      23
#define QPACK_STATIC_STATUS_200        25
#define QPACK_STATIC_STATUS_304        26
#define QPACK_STATIC_STATUS_404        27
#define QPACK_STATIC_STATUS_425        70
#define QPACK_STATIC_STATUS_503        28
#define QPACK_STATIC_CONTENT_TYPE_HTML 52
#define QPACK_STATIC_PATH_INDEX_HTML   63

/* QPACK header field representation prefixes (RFC 9204 Section 4.5) */
#define QPACK_INDEXED_STATIC        0xc0 /* 11xxxxxx: indexed, static table */
#define QPACK_INDEXED_STATIC_MASK   0xc0
#define QPACK_LIT_NAME_REF_STATIC   0x50 /* 0101xxxx: literal with name ref, static */
#define QPACK_LIT_NAME_REF_MASK     0xf0
#define QPACK_LIT_WITHOUT_NAME_REF  0x20 /* 001xxxxx: literal without name ref */
#define QPACK_LIT_WITHOUT_NAME_MASK 0xe0

struct qpack_static_entry {
	const char *name;
	const char *value;
};

/* QUIC variable-length integers (RFC 9000, Section 16). Return the number
 * of bytes used, -EINVAL when the input is short and -ENOSPC when the
 * output is.
 */
int http3_varint_decode(const uint8_t *buf, size_t buflen, uint64_t *value);
int http3_varint_encode(uint8_t *buf, size_t buflen, uint64_t value);

/* Frame type and length (RFC 9114, Section 7.1). Returns the bytes used, or
 * -EINVAL when the header is not complete yet.
 */
int http3_frame_header_parse(const uint8_t *buf, size_t buflen, uint64_t *type,
			     uint64_t *frame_len);

/* QPACK prefixed integers (RFC 9204, Section 4.1.1). */
int qpack_decode_int(const uint8_t *buf, size_t buflen, int prefix_n, uint64_t *value);
int qpack_encode_int(uint8_t *buf, size_t buflen, int prefix_n, uint8_t prefix, uint64_t value);

/* Number of entries of the QPACK static table. */
#define QPACK_STATIC_TABLE_LEN 99

/* Entry of the QPACK static table (RFC 9204, Appendix A), -ENOENT if none. */
int qpack_static_entry_get(uint64_t index, const struct qpack_static_entry **entry);

/* Huffman decoder from http_huffman.c (same table used by HPACK and QPACK) */
int http_hpack_huffman_decode(const uint8_t *encoded_buf, size_t encoded_len, uint8_t *buf,
			      size_t buflen);

#endif /* HTTP3_INTERNAL_H_ */
