/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* HTTP/3 protocol layer of the HTTP client (RFC 9114), on a multi-stream
 * transport such as QUIC. Each request runs on a bidirectional stream of its
 * own; the client opens a control stream and reads the server's.
 *
 * The client keeps no QPACK dynamic table (RFC 9204): it advertises a
 * capacity of 0, so it opens no QPACK streams, encodes from the static table
 * and literals only, and fails a field section that refers to the dynamic
 * table.
 */

#include <errno.h>
#include <string.h>
#include <strings.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/http/client_multiprotocol.h>
#include <zephyr/net/net_log.h>

#include "headers/client_internal.h"
#include "headers/http3_internal.h"

LOG_MODULE_DECLARE(net_http_client_mp, CONFIG_NET_HTTP_LOG_LEVEL);

/* HTTP/2 frame types, reserved in HTTP/3 (RFC 9114, Section 7.2.8). */
#define H3_FRAME_RESERVED_PRIORITY      0x02
#define H3_FRAME_RESERVED_PING          0x06
#define H3_FRAME_RESERVED_WINDOW_UPDATE 0x08
#define H3_FRAME_RESERVED_CONTINUATION  0x09

/* Stream ID bits (RFC 9000, Section 2.1). */
#define QUIC_STREAM_ID_SERVER 0x01
#define QUIC_STREAM_ID_UNI    0x02

/* Largest frame header: two 8-byte varints. */
#define H3_FRAME_HEADER_MAX 16

static const struct http_client_transport_ops *transport(struct http_client *client)
{
	return client->transport_ops;
}

static struct http3_client_parser *h3_parser(struct http_client *client)
{
	return &client->session.parser.http3;
}

/* Fail the connection: the session is ended and every request aborted. */
static int h3_connection_error(struct http_client *client, uint64_t code, const char *why)
{
	NET_ERR("HTTP/3 connection error 0x%llx: %s", (unsigned long long)code, why);
	http_client_session_terminate(client, -EBADMSG, true);

	return 0;
}

/* Release the transport stream of a request, telling the peer the reason. */
static void h3_stream_detach(struct http_client *client, struct http_client_stream *stream,
			     uint64_t code)
{
	if (stream->transport_stream != NULL) {
		transport(client)->stream_close(client, stream->transport_stream, code);
		stream->transport_stream = NULL;
	}
}

/* Fail a single request: its stream is abandoned and the transaction ended. */
static void h3_stream_error(struct http_client *client, struct http_client_stream *stream,
			    uint64_t code, int error, const char *why)
{
	NET_ERR("HTTP/3 stream %llu error 0x%llx: %s", (unsigned long long)stream->stream_id,
		(unsigned long long)code, why);
	h3_stream_detach(client, stream, code);
	http_client_stream_set_complete(client, stream, error);
}

/* Sending */

static int h3_frame_header_encode(uint8_t *buf, size_t buflen, uint64_t type, uint64_t len)
{
	int a = http3_varint_encode(buf, buflen, type);
	int b;

	if (a < 0) {
		return a;
	}

	b = http3_varint_encode(buf + a, buflen - a, len);

	return (b < 0) ? b : a + b;
}

/* A QPACK string literal without Huffman coding (RFC 9204, Section 4.1.2):
 * the H bit, then the length with the given prefix.
 */
static int qpack_encode_string(uint8_t *buf, size_t buflen, int prefix_n, uint8_t prefix,
			       const char *str)
{
	size_t len = strlen(str);
	int ret;

	ret = qpack_encode_int(buf, buflen, prefix_n, prefix, len);
	if (ret < 0) {
		return ret;
	}

	if (len > buflen - ret) {
		return -ENOSPC;
	}

	memcpy(buf + ret, str, len);

	return ret + (int)len;
}

/* Encode a field line from the static table where it has the field or its
 * name, as a literal otherwise (RFC 9204, Section 4.5).
 */
ZTESTABLE_STATIC int qpack_encode_field(uint8_t *buf, size_t buflen, const char *name,
					const char *value)
{
	const struct qpack_static_entry *entry;
	int name_idx = -1;
	int pos;
	int ret;

	for (uint64_t i = 0; i < QPACK_STATIC_TABLE_LEN; i++) {
		if (qpack_static_entry_get(i, &entry) != 0 || strcmp(entry->name, name) != 0) {
			continue;
		}

		if (entry->value != NULL && strcmp(entry->value, value) == 0) {
			/* Indexed field line, static table: 11xxxxxx. */
			return qpack_encode_int(buf, buflen, 6, QPACK_INDEXED_STATIC, i);
		}

		if (name_idx < 0) {
			name_idx = (int)i;
		}
	}

	if (name_idx >= 0) {
		/* Literal with a static name reference: 0101xxxx. */
		ret = qpack_encode_int(buf, buflen, 4, QPACK_LIT_NAME_REF_STATIC, name_idx);
	} else {
		/* Literal with a literal name: 0010xxxx, H = 0. */
		ret = qpack_encode_string(buf, buflen, 3, QPACK_LIT_WITHOUT_NAME_REF, name);
	}

	if (ret < 0) {
		return ret;
	}

	pos = qpack_encode_string(buf + ret, buflen - ret, 7, 0x00, value);

	return (pos < 0) ? pos : ret + pos;
}

struct h3_field_section_tx {
	uint8_t *buf;
	size_t buflen;
	size_t len;
};

static int h3_add_field(const char *name, const char *value, void *user_data)
{
	struct h3_field_section_tx *tx = user_data;
	int ret;

	ret = qpack_encode_field(tx->buf + tx->len, tx->buflen - tx->len, name, value);
	if (ret < 0) {
		/* shortcut: a HEADERS frame has no continuation, so the whole
		 * field section has to fit the TX buffer; encoding it twice to
		 * size the frame first would run headers_cb twice.
		 */
		return -ENOBUFS;
	}

	tx->len += ret;

	return 0;
}

static int h3_send(struct http_client *client, void *ts, const uint8_t *data, size_t len,
		   bool end_stream)
{
	return transport(client)->send(client, ts, data, len, end_stream);
}

/* Whether the request may still go out; takes the client lock. */
static int h3_stream_check(struct http_client *client, struct http_client_stream *stream)
{
	int ret = 0;

	k_mutex_lock(&client->lock, K_FOREVER);

	if (stream->completed) {
		ret = (stream->result < 0) ? stream->result : -EALREADY;
	} else if (client->session.state != HTTP_CLIENT_SESSION_OPEN) {
		ret = -ECONNABORTED;
	} else if (h3_parser(client)->going_away) {
		ret = -ESHUTDOWN;
	}

	k_mutex_unlock(&client->lock);

	return ret;
}

static int send_headers(struct http_client *client, struct http_client_stream *stream,
			bool end_stream)
{
	uint8_t *tx_buf = client->session.tx_buf;
	struct h3_field_section_tx tx = {
		.buf = tx_buf + H3_FRAME_HEADER_MAX,
		.buflen = sizeof(client->session.tx_buf) - H3_FRAME_HEADER_MAX,
	};
	void *ts = NULL;
	uint64_t id;
	int hdr_len;
	int ret;

	/* Encoded field section prefix: Required Insert Count 0, Base 0. */
	tx.buf[tx.len++] = 0x00;
	tx.buf[tx.len++] = 0x00;

	http_client_tx_acquire(client);

	ret = http_client_request_fields_foreach(client, stream, true, h3_add_field, &tx);
	if (ret < 0) {
		goto out;
	}

	ret = h3_stream_check(client, stream);
	if (ret < 0) {
		goto out;
	}

	ret = transport(client)->stream_open(client, true, &ts);
	if (ret < 0) {
		goto out;
	}

	ret = transport(client)->stream_id(client, ts, &id);
	if (ret < 0) {
		transport(client)->stream_close(client, ts, H3_REQUEST_CANCELLED);
		goto out;
	}

	k_mutex_lock(&client->lock, K_FOREVER);
	stream->transport_stream = ts;
	stream->stream_id = id;
	k_mutex_unlock(&client->lock);

	/* The frame header goes right in front of the field section. */
	{
		uint8_t hdr[H3_FRAME_HEADER_MAX];

		hdr_len = h3_frame_header_encode(hdr, sizeof(hdr), H3_FRAME_HEADERS, tx.len);
		memcpy(tx.buf - hdr_len, hdr, hdr_len);
	}

	ret = h3_send(client, ts, tx.buf - hdr_len, hdr_len + tx.len, end_stream);
	if (ret < 0) {
		/* Nothing will reset the stream, as its headers are not
		 * considered sent: release it here.
		 */
		k_mutex_lock(&client->lock, K_FOREVER);
		h3_stream_detach(client, stream, H3_REQUEST_CANCELLED);
		k_mutex_unlock(&client->lock);
	}

out:
	http_client_tx_release(client);

	return ret;
}

static int send_data(struct http_client *client, struct http_client_stream *stream,
		     const uint8_t *data, size_t len, bool end_stream)
{
	uint8_t hdr[H3_FRAME_HEADER_MAX];
	void *ts;
	int ret;

	if (len > 0 && data == NULL) {
		return -EINVAL;
	}

	http_client_tx_acquire(client);

	ret = h3_stream_check(client, stream);
	if (ret == -EALREADY || ret == -ESHUTDOWN) {
		/* The response is complete already, or the server goes away
		 * after it: the rest of the body is not needed.
		 */
		ret = (ret == -ESHUTDOWN) ? 0 : ret;
	}

	k_mutex_lock(&client->lock, K_FOREVER);
	ts = stream->transport_stream;
	k_mutex_unlock(&client->lock);

	if (ret < 0 || ts == NULL) {
		ret = (ret < 0) ? ret : -ECONNABORTED;
		goto out;
	}

	if (len > 0) {
		int hdr_len = h3_frame_header_encode(hdr, sizeof(hdr), H3_FRAME_DATA, len);

		ret = h3_send(client, ts, hdr, hdr_len, false);
		if (ret == 0) {
			ret = h3_send(client, ts, data, len, end_stream);
		}
	} else if (end_stream) {
		ret = h3_send(client, ts, NULL, 0, true);
	}

out:
	http_client_tx_release(client);

	return ret;
}

/* Receiving: response field sections */

static bool field_name_is(const struct h3_field *field, const char *name)
{
	size_t len = strlen(name);

	return field->name_len == len && strncasecmp(field->name, name, len) == 0;
}

static void copy_field_value(char *dst, size_t dst_size, const struct h3_field *field)
{
	size_t copy = MIN(field->value_len, dst_size - 1);

	memcpy(dst, field->value, copy);
	dst[copy] = '\0';
}

/* Parse an unsigned decimal number. Returns false on a non-digit or when the
 * value does not fit a size_t.
 */
static bool parse_decimal(const char *value, size_t value_len, size_t *result)
{
	size_t acc = 0;

	for (size_t i = 0; i < value_len; i++) {
		size_t digit;

		if (value[i] < '0' || value[i] > '9') {
			return false;
		}

		digit = (size_t)(value[i] - '0');
		if (acc > (SIZE_MAX - digit) / 10U) {
			return false;
		}

		acc = acc * 10U + digit;
	}

	*result = acc;

	return true;
}

/* A field as HTTP/3 allows it on the wire (RFC 9114, Section 4.2): lowercase
 * name of visible characters, a colon only as the first one, and a value with
 * no NUL, CR or LF that neither starts nor ends with whitespace.
 */
static bool field_is_valid(const struct h3_field *field)
{
	if (field->name_len == 0) {
		return false;
	}

	for (size_t i = 0; i < field->name_len; i++) {
		unsigned char c = (unsigned char)field->name[i];

		if (c <= 0x20U || c >= 0x7fU || (c >= 'A' && c <= 'Z') || (c == ':' && i > 0)) {
			return false;
		}
	}

	if (field->value_len > 0) {
		unsigned char first = (unsigned char)field->value[0];
		unsigned char last = (unsigned char)field->value[field->value_len - 1];

		if (first == ' ' || first == '\t' || last == ' ' || last == '\t') {
			return false;
		}
	}

	for (size_t i = 0; i < field->value_len; i++) {
		unsigned char c = (unsigned char)field->value[i];

		if (c == 0x00U || c == '\n' || c == '\r') {
			return false;
		}
	}

	return true;
}

/* Take a response field into the response summary (RFC 9114, Section 4.3.2). */
static int process_response_field(struct http_client_stream *stream, const struct h3_field *field)
{
	struct http_client_response *resp = &stream->response;
	struct http3_client_stream *h3 = &stream->proto.http3;
	size_t value;

	if (!field_is_valid(field)) {
		NET_ERR("Malformed header field");
		return -EBADMSG;
	}

	if (field->name[0] == ':') {
		if (stream->headers_received || h3->regular_field_seen ||
		    !field_name_is(field, ":status") || h3->status_seen) {
			NET_ERR("Unexpected response pseudo-header");
			return -EBADMSG;
		}

		if (field->value_len != 3 || !parse_decimal(field->value, 3, &value)) {
			NET_ERR("Invalid :status value");
			return -EBADMSG;
		}

		resp->status_code = (uint16_t)value;
		h3->status_seen = true;

		return 0;
	}

	h3->regular_field_seen = true;

	if (http_client_field_is_connection_specific(field->name, field->name_len) ||
	    field_name_is(field, "te")) {
		NET_ERR("Connection-specific header field");
		return -EBADMSG;
	}

	if (field_name_is(field, "content-type")) {
		copy_field_value(resp->content_type, sizeof(resp->content_type), field);
	} else if (field_name_is(field, "content-encoding")) {
		copy_field_value(resp->content_encoding, sizeof(resp->content_encoding), field);
	} else if (field_name_is(field, "content-length")) {
		if (stream->headers_received || field->value_len == 0 ||
		    !parse_decimal(field->value, field->value_len, &value) ||
		    (resp->content_len_present && value != resp->content_len)) {
			NET_ERR("Invalid content-length");
			return -EBADMSG;
		}

		resp->content_len = value;
		resp->content_len_present = true;
	}

	return 0;
}

/* Store a regular field in the stream headers buffer for the application:
 * the array from the start, the strings from the end. -ENOMEM when full.
 */
static int capture_field(struct http_client_stream *stream, const struct h3_field *field)
{
	struct http_client_response *resp = &stream->response;
	struct http_client_header *entries = (struct http_client_header *)stream->headers_buf;
	size_t *top = &stream->proto.http3.rx_headers_str_top;
	char *buf = (char *)stream->headers_buf;
	size_t array_bytes = (resp->header_count + 1) * sizeof(struct http_client_header);
	size_t str_bytes = field->name_len + 1 + field->value_len + 1;
	size_t name_off;
	size_t value_off;

	if (field->name[0] == ':') {
		return 0;
	}

	if (*top < str_bytes || *top - str_bytes < array_bytes) {
		return -ENOMEM;
	}

	value_off = *top - (field->value_len + 1);
	name_off = value_off - (field->name_len + 1);
	*top = name_off;

	memcpy(buf + name_off, field->name, field->name_len);
	buf[name_off + field->name_len] = '\0';
	memcpy(buf + value_off, field->value, field->value_len);
	buf[value_off + field->value_len] = '\0';

	entries[resp->header_count].name = buf + name_off;
	entries[resp->header_count].value = buf + value_off;
	resp->header_count++;
	resp->headers = entries;

	return 0;
}

static void reset_captured_fields(struct http_client_stream *stream)
{
	stream->response.headers = NULL;
	stream->response.header_count = 0;
	stream->proto.http3.rx_headers_str_top = sizeof(stream->headers_buf);
}

/* Whether the response carries no content whatever its headers say. */
static bool response_without_content(const struct http_client_stream *stream)
{
	return (stream->request != NULL && stream->request->method == HTTP_HEAD) ||
	       stream->response.status_code == 204 || stream->response.status_code == 304;
}

static bool body_length_ok(const struct http_client_stream *stream, bool final)
{
	const struct http_client_response *resp = &stream->response;
	size_t received = stream->proto.http3.body_received;

	if (!resp->content_len_present || response_without_content(stream)) {
		return true;
	}

	return final ? (received == resp->content_len) : (received <= resp->content_len);
}

/* Decode a QPACK string literal of a field line (RFC 9204, Section 4.1.2).
 * A Huffman-coded one is decoded into out, a plain one is pointed to.
 * Returns the bytes used, -EAGAIN when incomplete, -EBADMSG or -ENOBUFS.
 */
static int qpack_decode_string(const uint8_t *buf, size_t buflen, int prefix_n, const char **str,
			       size_t *str_len, uint8_t *out, size_t outlen, size_t *out_used)
{
	bool huffman = (buf[0] & BIT(prefix_n)) != 0;
	uint64_t len;
	int hdr;
	int ret;

	hdr = qpack_decode_int(buf, buflen, prefix_n, &len);
	if (hdr == -EINVAL) {
		return -EAGAIN;
	} else if (hdr < 0) {
		return -EBADMSG;
	}

	if (len > buflen - hdr) {
		return -EAGAIN;
	}

	if (!huffman) {
		*str = (const char *)buf + hdr;
		*str_len = (size_t)len;
		return hdr + (int)len;
	}

	ret = http_hpack_huffman_decode(buf + hdr, (size_t)len, out + *out_used,
					outlen - *out_used);
	if (ret == -ENOBUFS || ret == -ENOMEM) {
		return -ENOBUFS;
	} else if (ret < 0) {
		return -EBADMSG;
	}

	*str = (const char *)out + *out_used;
	*str_len = (size_t)ret;
	*out_used += ret;

	return hdr + (int)len;
}

/* Decode one field line with no dynamic table references. Returns the bytes
 * used, -EAGAIN when incomplete, -EBADMSG on a malformed or dynamic line and
 * -ENOBUFS on a field too large to decode.
 */
ZTESTABLE_STATIC int qpack_decode_field(const uint8_t *buf, size_t buflen, struct h3_field *field,
					uint8_t *scratch, size_t scratch_len)
{
	const struct qpack_static_entry *entry;
	size_t used = 0;
	uint64_t index;
	int pos;
	int ret;

	if (buflen == 0) {
		return -EAGAIN;
	}

	if ((buf[0] & 0x80) != 0) {
		/* Indexed field line: 1Txxxxxx, T = 1 for the static table. */
		if ((buf[0] & 0x40) == 0) {
			return -EBADMSG;
		}

		ret = qpack_decode_int(buf, buflen, 6, &index);
		if (ret == -EINVAL) {
			return -EAGAIN;
		}

		if (ret < 0 || qpack_static_entry_get(index, &entry) != 0) {
			return -EBADMSG;
		}

		/* An entry with no value stands for an empty one. */
		field->name = entry->name;
		field->name_len = strlen(entry->name);
		field->value = (entry->value != NULL) ? entry->value : "";
		field->value_len = strlen(field->value);

		return ret;
	}

	if ((buf[0] & 0xc0) == 0x40) {
		/* Literal with a name reference: 01NTxxxx. */
		if ((buf[0] & 0x10) == 0) {
			return -EBADMSG;
		}

		pos = qpack_decode_int(buf, buflen, 4, &index);
		if (pos == -EINVAL) {
			return -EAGAIN;
		}

		if (pos < 0 || qpack_static_entry_get(index, &entry) != 0) {
			return -EBADMSG;
		}

		field->name = entry->name;
		field->name_len = strlen(entry->name);
	} else if ((buf[0] & 0xe0) == 0x20) {
		/* Literal with a literal name: 001NHxxx. */
		pos = qpack_decode_string(buf, buflen, 3, &field->name, &field->name_len, scratch,
					  scratch_len, &used);
		if (pos < 0) {
			return pos;
		}
	} else {
		/* Post-base references need the dynamic table. */
		return -EBADMSG;
	}

	if ((size_t)pos >= buflen) {
		return -EAGAIN;
	}

	ret = qpack_decode_string(buf + pos, buflen - pos, 7, &field->value, &field->value_len,
				  scratch, scratch_len, &used);
	if (ret < 0) {
		return ret;
	}

	return pos + ret;
}

/* Deliver the field section received: headers, interim response or trailers. */
static int deliver_field_section(struct http_client *client, struct http_client_stream *stream)
{
	bool trailers = stream->headers_received;
	int ret;

	if (!trailers && stream->response.status_code == 0) {
		h3_stream_error(client, stream, H3_MESSAGE_ERROR, -EPROTO, ":status missing");
		return 0;
	}

	ret = http_client_stream_deliver(client, stream, false);
	if (ret < 0) {
		h3_stream_error(client, stream, H3_REQUEST_CANCELLED, ret,
				"aborted by the callback");
		return 0;
	}

	if (!trailers && stream->response.status_code >= 200) {
		stream->headers_received = true;
	}

	return 0;
}

/* A HEADERS frame starts: forget what the previous field section left. */
static void field_section_start(struct http_client_stream *stream)
{
	struct http3_client_stream *h3 = &stream->proto.http3;
	struct http_client_response *resp = &stream->response;

	if (!stream->headers_received) {
		resp->status_code = 0;
		resp->content_type[0] = '\0';
		resp->content_encoding[0] = '\0';
		resp->content_len = 0;
		resp->content_len_present = false;
	}

	h3->status_seen = false;
	h3->regular_field_seen = false;
	h3->prefix_seen = false;
	reset_captured_fields(stream);
}

/* Process part of a HEADERS frame payload, at most the frame's remainder. */
static int process_headers(struct http_client *client, struct http_client_stream *stream,
			   const uint8_t *data, size_t len)
{
	struct http3_client_stream *h3 = &stream->proto.http3;
	struct h3_field field;
	bool whole = len >= h3->rx.remaining;
	int ret;

	len = MIN(len, (size_t)h3->rx.remaining);

	if (!h3->prefix_seen) {
		uint64_t ric;
		uint64_t base;
		int pos;

		pos = qpack_decode_int(data, len, 8, &ric);
		ret = (pos < 0) ? pos : qpack_decode_int(data + pos, len - pos, 7, &base);
		if (ret == -EINVAL) {
			if (whole) {
				return h3_connection_error(client, QPACK_DECOMPRESSION_FAILED,
							   "truncated field section prefix");
			}

			return -EAGAIN;
		}

		if (ret < 0 || ric != 0) {
			/* No dynamic table was granted to refer to. */
			return h3_connection_error(client, QPACK_DECOMPRESSION_FAILED,
						   "dynamic table reference");
		}

		h3->prefix_seen = true;
		ret += pos;
	} else {
		ret = qpack_decode_field(data, len, &field, h3_parser(client)->huffman_buf,
					 sizeof(h3_parser(client)->huffman_buf));
		if (ret == -EAGAIN) {
			if (whole) {
				return h3_connection_error(client, QPACK_DECOMPRESSION_FAILED,
							   "field line runs past the frame");
			}

			return -EAGAIN;
		}

		if (ret == -EBADMSG) {
			return h3_connection_error(client, QPACK_DECOMPRESSION_FAILED,
						   "malformed field line");
		}

		if (ret == -ENOBUFS) {
			/* A limit of this client: the line length is not known,
			 * so the stream cannot be decoded further.
			 */
			h3_stream_error(client, stream, H3_EXCESSIVE_LOAD, -ENOBUFS,
					"response header field too large");
			return (int)len;
		}

		if (process_response_field(stream, &field) < 0) {
			h3_stream_error(client, stream, H3_MESSAGE_ERROR, -EPROTO,
					"malformed response headers");
			return (int)len;
		}

		if (stream->request != NULL && !stream->request->skip_response_headers) {
			int cret = capture_field(stream, &field);

			if (cret == -ENOMEM && stream->response.header_count > 0) {
				/* Hand over what fits and start over. */
				cret = http_client_stream_deliver(client, stream, false);
				if (cret < 0 || stream->completed) {
					h3_stream_error(client, stream, H3_REQUEST_CANCELLED,
							(cret < 0) ? cret : -ECONNABORTED,
							"aborted by the callback");
					return (int)len;
				}

				reset_captured_fields(stream);
				cret = capture_field(stream, &field);
			}

			if (cret == -ENOMEM) {
				h3_stream_error(client, stream, H3_EXCESSIVE_LOAD, -ENOBUFS,
						"response header field too large");
				return (int)len;
			}
		}
	}

	h3->rx.remaining -= ret;
	if (h3->rx.remaining == 0) {
		h3->rx.in_frame = false;

		if (!h3->prefix_seen) {
			return h3_connection_error(client, QPACK_DECOMPRESSION_FAILED,
						   "empty field section");
		}

		(void)deliver_field_section(client, stream);
	}

	return ret;
}

/* The request stream ended: complete the transaction. */
static void request_stream_end(struct http_client *client, struct http_client_stream *stream)
{
	struct http3_client_stream *h3 = &stream->proto.http3;

	if (stream->completed) {
		return;
	}

	if (h3->rx.in_frame) {
		h3_stream_error(client, stream, H3_FRAME_ERROR, -EPROTO,
				"stream ended within a frame");
		return;
	}

	if (!stream->headers_received) {
		h3_stream_error(client, stream, H3_MESSAGE_ERROR, -EPROTO,
				"stream ended without a response");
		return;
	}

	if (!body_length_ok(stream, true)) {
		h3_stream_error(client, stream, H3_MESSAGE_ERROR, -EPROTO,
				"body length does not match content-length");
		return;
	}

	stream->response.body = NULL;
	stream->response.body_len = 0;

	/* The stream may be released in here. */
	(void)http_client_stream_deliver(client, stream, true);
}

/* Process data of a request stream, one frame header or payload part at a time. */
static int process_request_stream(struct http_client *client, struct http_client_stream *stream,
				  const uint8_t *data, size_t len, bool end_stream)
{
	struct http3_client_stream *h3 = &stream->proto.http3;
	int ret;

	if (len == 0) {
		ret = 0;
	} else if (!h3->rx.in_frame) {
		ret = http3_frame_header_parse(data, len, &h3->rx.type, &h3->rx.remaining);
		if (ret == -EINVAL) {
			if (end_stream) {
				h3_stream_error(client, stream, H3_FRAME_ERROR, -EPROTO,
						"stream ended within a frame header");
				return (int)len;
			}

			return -EAGAIN;
		}

		switch (h3->rx.type) {
		case H3_FRAME_HEADERS:
			field_section_start(stream);
			break;

		case H3_FRAME_DATA:
			if (!stream->headers_received) {
				h3_stream_error(client, stream, H3_FRAME_UNEXPECTED, -EPROTO,
						"DATA before the response headers");
				return (int)len;
			}

			break;

		case H3_FRAME_PUSH_PROMISE:
			/* No push was allowed with MAX_PUSH_ID. */
			return h3_connection_error(client, H3_ID_ERROR, "PUSH_PROMISE");

		case H3_FRAME_CANCEL_PUSH:
		case H3_FRAME_SETTINGS:
		case H3_FRAME_GOAWAY:
		case H3_FRAME_MAX_PUSH_ID:
		case H3_FRAME_RESERVED_PRIORITY:
		case H3_FRAME_RESERVED_PING:
		case H3_FRAME_RESERVED_WINDOW_UPDATE:
		case H3_FRAME_RESERVED_CONTINUATION:
			return h3_connection_error(client, H3_FRAME_UNEXPECTED,
						   "frame not allowed on a request stream");

		default:
			/* Unknown frame types are ignored (Section 9). */
			break;
		}

		h3->rx.in_frame = true;

		if (h3->rx.remaining == 0) {
			h3->rx.in_frame = false;

			if (h3->rx.type == H3_FRAME_HEADERS) {
				return h3_connection_error(client, QPACK_DECOMPRESSION_FAILED,
							   "empty field section");
			}
		}
	} else if (h3->rx.type == H3_FRAME_HEADERS) {
		ret = process_headers(client, stream, data, len);
		if (ret == -EAGAIN && end_stream) {
			h3_stream_error(client, stream, H3_FRAME_ERROR, -EPROTO,
					"stream ended within a frame");
			return (int)len;
		}

		if (ret < 0 || client->session.state != HTTP_CLIENT_SESSION_OPEN ||
		    stream->completed) {
			return (ret < 0) ? ret : (int)len;
		}
	} else {
		size_t chunk = MIN(len, (size_t)h3->rx.remaining);

		h3->rx.remaining -= chunk;
		if (h3->rx.remaining == 0) {
			h3->rx.in_frame = false;
		}

		ret = (int)chunk;

		if (h3->rx.type == H3_FRAME_DATA && chunk > 0) {
			int dret;

			h3->body_received += chunk;
			if (!body_length_ok(stream, false)) {
				h3_stream_error(client, stream, H3_MESSAGE_ERROR, -EPROTO,
						"body longer than content-length");
				return (int)len;
			}

			stream->response.body = data;
			stream->response.body_len = chunk;

			dret = http_client_stream_deliver(client, stream, false);
			if (dret < 0) {
				h3_stream_error(client, stream, H3_REQUEST_CANCELLED, dret,
						"aborted by the callback");
				return (int)len;
			}
		}
	}

	if (end_stream && (size_t)ret == len && !stream->completed) {
		request_stream_end(client, stream);
	}

	return ret;
}

/* Fail the requests the server will not process after its GOAWAY. */
static void goaway_streams(struct http_client *client, uint64_t id)
{
	ARRAY_FOR_EACH(client->session.streams, i) {
		struct http_client_stream *stream = &client->session.streams[i];

		if (stream->is_used && !stream->completed && stream->transport_stream != NULL &&
		    stream->stream_id >= id) {
			h3_stream_error(client, stream, H3_REQUEST_CANCELLED, -ESHUTDOWN,
					"not processed by the server");
		}
	}
}

static bool has_active_streams(struct http_client *client)
{
	ARRAY_FOR_EACH(client->session.streams, i) {
		const struct http_client_stream *stream = &client->session.streams[i];

		if (stream->is_used && !stream->completed) {
			return true;
		}
	}

	return false;
}

/* Process a whole control frame payload (Section 7.2). */
static int process_control_frame(struct http_client *client, uint64_t type, const uint8_t *data,
				 size_t len)
{
	struct http3_client_parser *parser = h3_parser(client);
	size_t pos = 0;

	if (!parser->settings_received && type != H3_FRAME_SETTINGS) {
		return h3_connection_error(client, H3_MISSING_SETTINGS,
					   "control stream without SETTINGS");
	}

	switch (type) {
	case H3_FRAME_SETTINGS: {
		uint64_t seen = 0;

		if (parser->settings_received) {
			return h3_connection_error(client, H3_FRAME_UNEXPECTED, "second SETTINGS");
		}

		while (pos < len) {
			uint64_t id;
			uint64_t value;
			int ret;

			ret = http3_varint_decode(data + pos, len - pos, &id);
			if (ret > 0) {
				pos += ret;
				ret = http3_varint_decode(data + pos, len - pos, &value);
			}

			if (ret < 0) {
				return h3_connection_error(client, H3_FRAME_ERROR,
							   "malformed SETTINGS");
			}

			pos += ret;

			/* HTTP/2 settings have no place here (Section 7.2.4.1). */
			if (id >= 0x02 && id <= 0x05) {
				return h3_connection_error(client, H3_SETTINGS_ERROR,
							   "HTTP/2 setting");
			}

			if (id < 64) {
				if ((seen & BIT64(id)) != 0) {
					return h3_connection_error(client, H3_SETTINGS_ERROR,
								   "duplicate setting");
				}

				seen |= BIT64(id);
			}

			if (id == H3_SETTINGS_MAX_FIELD_SECTION_SIZE) {
				parser->peer_max_field_section_size = value;
			}
		}

		parser->settings_received = true;
		return 0;
	}

	case H3_FRAME_GOAWAY: {
		uint64_t id;

		if (http3_varint_decode(data, len, &id) != (int)len) {
			return h3_connection_error(client, H3_FRAME_ERROR, "malformed GOAWAY");
		}

		if ((id & 0x03) != 0 || (parser->going_away && id > parser->goaway_id)) {
			return h3_connection_error(client, H3_ID_ERROR, "invalid GOAWAY ID");
		}

		parser->going_away = true;
		parser->goaway_id = id;
		goaway_streams(client, id);
		return 0;
	}

	case H3_FRAME_DATA:
	case H3_FRAME_HEADERS:
	case H3_FRAME_PUSH_PROMISE:
	case H3_FRAME_MAX_PUSH_ID:
	case H3_FRAME_RESERVED_PRIORITY:
	case H3_FRAME_RESERVED_PING:
	case H3_FRAME_RESERVED_WINDOW_UPDATE:
	case H3_FRAME_RESERVED_CONTINUATION:
		return h3_connection_error(client, H3_FRAME_UNEXPECTED,
					   "frame not allowed on the control stream");

	default:
		/* CANCEL_PUSH, for no push ever allowed, and unknown types. */
		return 0;
	}
}

static int process_control_stream(struct http_client *client, struct http3_client_uni_stream *uni,
				  const uint8_t *data, size_t len)
{
	int ret;

	if (!uni->rx.in_frame) {
		ret = http3_frame_header_parse(data, len, &uni->rx.type, &uni->rx.remaining);
		if (ret == -EINVAL) {
			return -EAGAIN;
		}

		uni->rx.in_frame = true;
		data += ret;
		len -= ret;

		if (uni->rx.type != H3_FRAME_SETTINGS && uni->rx.type != H3_FRAME_GOAWAY) {
			/* Skipped as it arrives, below. */
			return ret;
		}

		/* SETTINGS and GOAWAY are handled whole, from the buffer. */
		if (uni->rx.remaining > len) {
			uni->rx.in_frame = false;
			return (uni->rx.remaining + ret > sizeof(client->session.rx_buf))
				       ? h3_connection_error(client, H3_EXCESSIVE_LOAD,
							     "control frame too large")
				       : -EAGAIN;
		}

		uni->rx.in_frame = false;
		(void)process_control_frame(client, uni->rx.type, data, (size_t)uni->rx.remaining);

		return ret + (int)uni->rx.remaining;
	}

	/* Skip the payload of a frame of no interest. */
	ret = (int)MIN(len, (size_t)uni->rx.remaining);
	uni->rx.remaining -= ret;
	if (uni->rx.remaining == 0) {
		uni->rx.in_frame = false;
	}

	return ret;
}

static void uni_stream_release(struct http_client *client, struct http3_client_uni_stream *uni,
			       uint64_t code)
{
	transport(client)->stream_close(client, uni->transport_stream, code);
	memset(uni, 0, sizeof(*uni));
}

/* Process data of a unidirectional stream opened by the server (Section 6.2). */
static int process_uni_stream(struct http_client *client, struct http3_client_uni_stream *uni,
			      const uint8_t *data, size_t len, bool end_stream)
{
	struct http3_client_parser *parser = h3_parser(client);
	int ret;

	if (!uni->typed) {
		if (len == 0) {
			ret = 0;
			goto out;
		}

		ret = http3_varint_decode(data, len, &uni->type);
		if (ret == -EINVAL) {
			if (end_stream) {
				uni_stream_release(client, uni, H3_NO_ERROR);
				return (int)len;
			}

			return -EAGAIN;
		}

		uni->typed = true;

		switch (uni->type) {
		case H3_UNI_STREAM_CONTROL:
			if (parser->control_seen) {
				return h3_connection_error(client, H3_STREAM_CREATION_ERROR,
							   "second control stream");
			}

			parser->control_seen = true;
			break;

		case H3_UNI_STREAM_QPACK_ENCODER:
		case H3_UNI_STREAM_QPACK_DECODER:
			/* With no dynamic table, nothing on them matters. */
			break;

		case H3_UNI_STREAM_PUSH:
			return h3_connection_error(client, H3_ID_ERROR, "push stream");

		default:
			/* Unknown types are refused (Section 6.2). */
			uni_stream_release(client, uni, H3_STREAM_CREATION_ERROR);
			return (int)len;
		}

		goto out;
	}

	if (uni->type == H3_UNI_STREAM_CONTROL && len > 0) {
		ret = process_control_stream(client, uni, data, len);
	} else {
		ret = (int)len;
	}

out:
	if (ret >= 0 && end_stream && (size_t)ret == len &&
	    client->session.state == HTTP_CLIENT_SESSION_OPEN) {
		/* The control and QPACK streams are critical (Section 6.2.1). */
		if (uni->typed) {
			return h3_connection_error(client, H3_CLOSED_CRITICAL_STREAM,
						   "critical stream closed");
		}

		uni_stream_release(client, uni, H3_NO_ERROR);
	}

	return ret;
}

static struct http_client_stream *request_stream_find(struct http_client *client, void *ts)
{
	ARRAY_FOR_EACH(client->session.streams, i) {
		struct http_client_stream *stream = &client->session.streams[i];

		if (stream->is_used && stream->transport_stream == ts) {
			return stream;
		}
	}

	return NULL;
}

static struct http3_client_uni_stream *uni_stream_find(struct http_client *client, void *ts)
{
	struct http3_client_parser *parser = h3_parser(client);
	struct http3_client_uni_stream *free_slot = NULL;
	uint64_t id;

	ARRAY_FOR_EACH(parser->peer, i) {
		if (parser->peer[i].transport_stream == ts) {
			return &parser->peer[i];
		}

		if (free_slot == NULL && parser->peer[i].transport_stream == NULL) {
			free_slot = &parser->peer[i];
		}
	}

	/* A stream not seen before: it has to be unidirectional and opened by
	 * the server, as the server opens no request streams (Section 6.1).
	 */
	if (transport(client)->stream_id(client, ts, &id) < 0) {
		return NULL;
	}

	if ((id & (QUIC_STREAM_ID_SERVER | QUIC_STREAM_ID_UNI)) == QUIC_STREAM_ID_SERVER) {
		(void)h3_connection_error(client, H3_STREAM_CREATION_ERROR,
					  "server-initiated bidirectional stream");
		return NULL;
	}

	if ((id & QUIC_STREAM_ID_SERVER) == 0) {
		/* One of the client's own, e. g. a request stream given up. */
		return NULL;
	}

	if (free_slot == NULL) {
		NET_WARN("No slot for server stream %llu, refused", (unsigned long long)id);
		transport(client)->stream_close(client, ts, H3_STREAM_CREATION_ERROR);
		return NULL;
	}

	free_slot->transport_stream = ts;

	return free_slot;
}

/* HTTP/3 operations */

static int http3_client_session_open(struct http_client *client)
{
	struct http3_client_parser *parser = h3_parser(client);
	/* Control stream type, then an empty SETTINGS frame: no dynamic table
	 * and no limit on field sections (Section 7.2.4.1).
	 */
	static const uint8_t preface[] = {H3_UNI_STREAM_CONTROL, H3_FRAME_SETTINGS, 0x00};
	int ret;

	if (transport(client)->stream_open == NULL || transport(client)->stream_close == NULL ||
	    transport(client)->stream_id == NULL) {
		NET_ERR("HTTP/3 needs a multi-stream transport");
		return -ENOTSUP;
	}

	memset(parser, 0, sizeof(*parser));
	parser->peer_max_field_section_size = UINT64_MAX;

	/* Opening the first stream runs the QUIC handshake. */
	ret = transport(client)->stream_open(client, false, &parser->control_stream);
	if (ret < 0) {
		NET_ERR("Failed to open the HTTP/3 control stream, err %d", ret);
		return ret;
	}

	ret = h3_send(client, parser->control_stream, preface, sizeof(preface), false);
	if (ret < 0) {
		NET_ERR("Failed to send HTTP/3 %s, err %d", "SETTINGS", ret);
	}

	return ret;
}

static int http3_client_session_close(struct http_client *client, int reason)
{
	struct http3_client_parser *parser = h3_parser(client);
	/* GOAWAY with push ID 0: the client never allowed a push. */
	static const uint8_t goaway[] = {H3_FRAME_GOAWAY, 0x01, 0x00};
	int ret;

	ARG_UNUSED(reason);

	if (parser->control_stream == NULL) {
		return 0;
	}

	ret = h3_send(client, parser->control_stream, goaway, sizeof(goaway), false);
	if (ret < 0) {
		NET_ERR("Failed to send HTTP/3 %s, err %d", "GOAWAY", ret);
	}

	return ret;
}

static int http3_client_stream_open(struct http_client *client, struct http_client_stream *stream)
{
	if (h3_parser(client)->going_away) {
		NET_DBG("Server is closing the connection, no new streams");
		return -ESHUTDOWN;
	}

	/* The identifier is the QUIC stream's, known once it is opened. */
	stream->stream_id = 0;
	stream->transport_stream = NULL;
	memset(&stream->proto.http3, 0, sizeof(stream->proto.http3));

	return 0;
}

static int http3_client_stream_close(struct http_client *client, struct http_client_stream *stream)
{
	h3_stream_detach(client, stream, H3_NO_ERROR);

	return 0;
}

static int http3_client_stream_reset(struct http_client *client, struct http_client_stream *stream)
{
	h3_stream_detach(client, stream, H3_REQUEST_CANCELLED);

	return 0;
}

static int http3_client_stream_send_headers(struct http_client *client,
					    struct http_client_stream *stream,
					    const struct http_client_request *req, bool end_stream)
{
	int ret;

	ARG_UNUSED(req);

	ret = send_headers(client, stream, end_stream);
	if (ret < 0) {
		NET_ERR("Failed to send HTTP/3 %s, err %d", "HEADERS", ret);
	}

	return ret;
}

static int http3_client_stream_send_data(struct http_client *client,
					 struct http_client_stream *stream, const uint8_t *data,
					 size_t len, bool end_stream)
{
	int ret;

	ret = send_data(client, stream, data, len, end_stream);
	if (ret < 0) {
		NET_ERR("Failed to send HTTP/3 %s, err %d", "DATA", ret);
	}

	return ret;
}

static int http3_client_process_data(struct http_client *client, void *transport_stream,
				     uint8_t *data, size_t len, bool end_stream)
{
	struct http_client_stream *stream;
	struct http3_client_uni_stream *uni;
	int ret;

	if (transport_stream == NULL) {
		return -EPROTO;
	}

	stream = request_stream_find(client, transport_stream);
	if (stream != NULL) {
		if (stream->completed) {
			/* Left over after the transaction ended. */
			return (int)len;
		}

		ret = process_request_stream(client, stream, data, len, end_stream);
	} else {
		uni = uni_stream_find(client, transport_stream);
		if (uni == NULL) {
			return (int)len;
		}

		ret = process_uni_stream(client, uni, data, len, end_stream);
	}

	if (ret >= 0 && client->session.state == HTTP_CLIENT_SESSION_OPEN &&
	    h3_parser(client)->going_away && !has_active_streams(client)) {
		/* Nothing is left to wait for on a connection the server is
		 * closing.
		 */
		http_client_session_terminate(client, 0, true);
	}

	return ret;
}

static struct http_client_ops http3_client_ops = {
	.session_open = http3_client_session_open,
	.session_close = http3_client_session_close,
	.stream_open = http3_client_stream_open,
	.stream_close = http3_client_stream_close,
	.stream_reset = http3_client_stream_reset,
	.stream_send_headers = http3_client_stream_send_headers,
	.stream_send_data = http3_client_stream_send_data,
	.process_data = http3_client_process_data,
};

const struct http_client_ops *http_client_get_http3_ops(void)
{
	return &http3_client_ops;
}
