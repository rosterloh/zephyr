/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* QUIC transport of the HTTP client, for HTTP/3. A connection socket carries
 * one stream socket per stream; streams the server opens are accepted from
 * the connection socket as they arrive.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/http/client_multiprotocol.h>
#include <zephyr/net/net_log.h>
#include <zephyr/net/quic.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/socket_service.h>

LOG_MODULE_DECLARE(net_http_client_mp, CONFIG_NET_HTTP_LOG_LEVEL);

#define INVALID_SOCK        (-1)
#define QUIC_MAX_INSTANCES  CONFIG_HTTP_CLIENT_MAX_INSTANCES
#define QUIC_STREAMS        HTTP_CLIENT_QUIC_MAX_STREAMS
#define QUIC_FDS_PER_CLIENT (1 + QUIC_STREAMS)

/* Longest domain name a TLS server name may carry, with its terminator. */
#define TLS_SERVER_NAME_MAX 256

/* Registry of the asynchronous sessions: the connection socket and the
 * stream sockets of each client, polled by the socket service. The streams
 * change during a session, so the set is registered again on every change.
 * The lock also guards the stream tables of all clients.
 */
static struct http_client *quic_clients[QUIC_MAX_INSTANCES];
static struct zsock_pollfd quic_fds[QUIC_MAX_INSTANCES * QUIC_FDS_PER_CLIENT];
static K_MUTEX_DEFINE(quic_lock);

/* The client a notification is in progress for and the thread delivering it. */
static struct http_client *quic_notifying;
static k_tid_t quic_notifying_thread;
static K_CONDVAR_DEFINE(quic_notified);

static void quic_transport_recv_cb(struct net_socket_service_event *pev);

NET_SOCKET_SERVICE_SYNC_DEFINE_STATIC(quic_socket_service, quic_transport_recv_cb,
				      QUIC_MAX_INSTANCES *QUIC_FDS_PER_CLIENT);

static struct http_client_transport_quic_ctx *quic_ctx(struct http_client *client)
{
	return client->transport_ctx;
}

/* Whether a stream is polled for reception. */
static bool stream_is_polled(const struct http_client_transport_quic_stream *st)
{
	return st->sock >= 0 && !st->send_only && !st->eof;
}

/* Rebuild the pollable socket array and (re)register it with the socket
 * service. Must be called with quic_lock held.
 */
static int quic_sync_locked(void)
{
	bool any = false;

	for (int i = 0; i < QUIC_MAX_INSTANCES; i++) {
		struct zsock_pollfd *fds = &quic_fds[i * QUIC_FDS_PER_CLIENT];
		struct http_client_transport_quic_ctx *ctx = NULL;

		if (quic_clients[i] != NULL) {
			ctx = quic_ctx(quic_clients[i]);
			any = true;
		}

		fds[0].fd = (ctx != NULL) ? ctx->sock : INVALID_SOCK;
		fds[0].events = (ctx != NULL) ? ZSOCK_POLLIN : 0;

		for (int j = 0; j < QUIC_STREAMS; j++) {
			bool polled = ctx != NULL && stream_is_polled(&ctx->streams[j]);

			fds[1 + j].fd = polled ? ctx->streams[j].sock : INVALID_SOCK;
			fds[1 + j].events = polled ? ZSOCK_POLLIN : 0;
		}
	}

	if (!any) {
		return net_socket_service_unregister(&quic_socket_service);
	}

	return net_socket_service_register(&quic_socket_service, quic_fds, ARRAY_SIZE(quic_fds),
					   NULL);
}

static bool quic_is_registered_locked(struct http_client *client)
{
	for (int i = 0; i < QUIC_MAX_INSTANCES; i++) {
		if (quic_clients[i] == client) {
			return true;
		}
	}

	return false;
}

/* The polled set of a client changed. Must be called with quic_lock held. */
static void quic_changed_locked(struct http_client *client)
{
	if (quic_is_registered_locked(client)) {
		(void)quic_sync_locked();
	}
}

static int quic_register(struct http_client *client)
{
	int ret = -ENOMEM;
	int slot;

	k_mutex_lock(&quic_lock, K_FOREVER);

	for (slot = 0; slot < QUIC_MAX_INSTANCES; slot++) {
		if (quic_clients[slot] == NULL) {
			break;
		}
	}

	if (slot == QUIC_MAX_INSTANCES) {
		NET_ERR("No free slot for asynchronous QUIC transport, "
			"increase %s",
			"CONFIG_HTTP_CLIENT_MAX_INSTANCES");
		goto out;
	}

	quic_clients[slot] = client;

	ret = quic_sync_locked();
	if (ret < 0) {
		NET_ERR("Failed to register socket service, err %d", ret);
		quic_clients[slot] = NULL;
	}

out:
	k_mutex_unlock(&quic_lock);

	return ret;
}

static void quic_unregister(struct http_client *client)
{
	bool found = false;

	k_mutex_lock(&quic_lock, K_FOREVER);

	for (int i = 0; i < QUIC_MAX_INSTANCES; i++) {
		if (quic_clients[i] == client) {
			quic_clients[i] = NULL;
			found = true;
		}
	}

	if (found) {
		(void)quic_sync_locked();
	}

	k_mutex_unlock(&quic_lock);
}

/* Map poll result flags of a socket to a reception status. */
static int quic_revents_status(int fd, short revents)
{
	if ((revents & ZSOCK_POLLNVAL) != 0) {
		return -EBADF;
	}

	if ((revents & ZSOCK_POLLERR) != 0) {
		int sock_err = 0;
		net_socklen_t optlen = sizeof(sock_err);
		int ret;

		ret = zsock_getsockopt(fd, ZSOCK_SOL_SOCKET, ZSOCK_SO_ERROR, &sock_err, &optlen);

		return (ret == 0 && sock_err > 0) ? -sock_err : -EIO;
	}

	return 0;
}

static void quic_transport_recv_cb(struct net_socket_service_event *pev)
{
	struct http_client *client = NULL;
	int status;

	k_mutex_lock(&quic_lock, K_FOREVER);

	for (int i = 0; i < ARRAY_SIZE(quic_fds); i++) {
		if (pev->event.fd >= 0 && quic_fds[i].fd == pev->event.fd) {
			client = quic_clients[i / QUIC_FDS_PER_CLIENT];
			break;
		}
	}

	quic_notifying = client;
	quic_notifying_thread = k_current_get();

	k_mutex_unlock(&quic_lock);

	if (client == NULL) {
		NET_DBG("No client found for socket %d", pev->event.fd);
		goto done;
	}

	status = quic_revents_status(pev->event.fd, pev->event.revents);
	if (status < 0) {
		NET_ERR("Error condition on socket %d (revents 0x%x), err %d", pev->event.fd,
			pev->event.revents, status);
	}

	if (status != 0 || (pev->event.revents & (ZSOCK_POLLIN | ZSOCK_POLLHUP)) != 0) {
		http_client_received_data(client, status);
	}

done:
	k_mutex_lock(&quic_lock, K_FOREVER);
	quic_notifying = NULL;
	k_condvar_broadcast(&quic_notified);
	k_mutex_unlock(&quic_lock);
}

static void quic_wait_notified(struct http_client *client)
{
	k_mutex_lock(&quic_lock, K_FOREVER);

	while (quic_notifying == client && quic_notifying_thread != k_current_get()) {
		(void)k_condvar_wait(&quic_notified, &quic_lock, K_FOREVER);
	}

	k_mutex_unlock(&quic_lock);
}

/* The name to send as the TLS server name, see the TLS transport. */
static const char *quic_server_name(const struct http_client *client,
				    const struct http_client_transport_tls_config *tls, char *buf,
				    size_t size)
{
	const char *host = client->session.host;
	struct net_in_addr addr4;
	size_t len;

	if (tls->hostname != NULL) {
		return tls->hostname;
	}

	if (host == NULL || host[0] == '[') {
		return NULL;
	}

	len = strlen(host);
	if (len == 0 || len >= size) {
		return NULL;
	}

	memcpy(buf, host, len + 1);

	if (net_addr_pton(NET_AF_INET, buf, &addr4) == 0) {
		return NULL;
	}

	return buf;
}

static int quic_setup(struct http_client *client, int sock,
		      const struct http_client_transport_tls_config *tls)
{
	/* HTTP/3 is negotiated with ALPN (RFC 9114, Section 3.1). */
	static const char *const alpn_h3[] = {"h3"};
	char name[TLS_SERVER_NAME_MAX];
	const char *server_name;
	int ret;

	if (tls->cipher_list != NULL && tls->cipher_count > 0) {
		ret = zsock_setsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
				       tls->cipher_list, sizeof(int) * tls->cipher_count);
		if (ret < 0) {
			ret = -errno;
			NET_ERR("Failed to set %s, err %d", "TLS_CIPHERSUITE_LIST", ret);
			return ret;
		}
	}

	if (tls->sec_tag_list != NULL && tls->sec_tag_count > 0) {
		ret = zsock_setsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SEC_TAG_LIST,
				       tls->sec_tag_list, sizeof(sec_tag_t) * tls->sec_tag_count);
		if (ret < 0) {
			ret = -errno;
			NET_ERR("Failed to set %s, err %d", "TLS_SEC_TAG_LIST", ret);
			return ret;
		}
	}

	ret = zsock_setsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_ALPN_LIST, alpn_h3, sizeof(alpn_h3));
	if (ret < 0) {
		ret = -errno;
		NET_ERR("Failed to set %s, err %d", "TLS_ALPN_LIST", ret);
		return ret;
	}

	server_name = quic_server_name(client, tls, name, sizeof(name));
	if (server_name != NULL) {
		ret = zsock_setsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_HOSTNAME, server_name,
				       strlen(server_name) + 1);
		if (ret < 0) {
			ret = -errno;
			NET_ERR("Failed to set %s, err %d", "TLS_HOSTNAME", ret);
			return ret;
		}
	}

	if (tls->cert_nocopy != ZSOCK_TLS_CERT_NOCOPY_NONE) {
		ret = zsock_setsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CERT_NOCOPY,
				       &tls->cert_nocopy, sizeof(tls->cert_nocopy));
		if (ret < 0) {
			ret = -errno;
			NET_ERR("Failed to set %s, err %d", "TLS_CERT_NOCOPY", ret);
			return ret;
		}
	}

	return 0;
}

static void quic_transport_init(void *transport_ctx)
{
	struct http_client_transport_quic_ctx *ctx = transport_ctx;

	NET_ASSERT(ctx != NULL);

	ctx->sock = INVALID_SOCK;

	ARRAY_FOR_EACH(ctx->streams, i) {
		ctx->streams[i].sock = INVALID_SOCK;
	}
}

/* Take a free stream slot for sock. Must be called with quic_lock held. */
static struct http_client_transport_quic_stream *
stream_slot_take(struct http_client_transport_quic_ctx *ctx, int sock, bool send_only)
{
	ARRAY_FOR_EACH(ctx->streams, i) {
		struct http_client_transport_quic_stream *st = &ctx->streams[i];

		if (st->sock < 0) {
			st->sock = sock;
			st->send_only = send_only;
			st->eof = false;
			return st;
		}
	}

	return NULL;
}

static void stream_slot_close(struct http_client_transport_quic_stream *st)
{
	NET_DBG("Closing stream socket %d", st->sock);
	(void)quic_stream_close(st->sock);
	st->sock = INVALID_SOCK;
}

static int quic_transport_connect(struct http_client *client)
{
	struct http_client_transport_quic_ctx *ctx = quic_ctx(client);
	int ret;

	ctx->sock = quic_connection_open((const struct net_sockaddr *)&client->session.server_addr,
					 NULL);
	if (ctx->sock < 0) {
		ret = ctx->sock;
		ctx->sock = INVALID_SOCK;
		NET_ERR("Failed to open QUIC connection, err %d", ret);
		return ret;
	}

	NET_DBG("Created QUIC connection %d", ctx->sock);

	ret = quic_setup(client, ctx->sock, &ctx->config);
	if (ret < 0) {
		goto error;
	}

	/* The handshake runs when the first stream is opened, the protocol
	 * layer's control stream.
	 */
	if (client->session.async) {
		ret = quic_register(client);
		if (ret < 0) {
			NET_ERR("Failed to setup async reception, err %d", ret);
			goto error;
		}
	}

	return 0;

error:
	(void)quic_connection_close(ctx->sock);
	ctx->sock = INVALID_SOCK;

	return ret;
}

static int quic_transport_stream_open(struct http_client *client, bool bidirectional, void **stream)
{
	struct http_client_transport_quic_ctx *ctx = quic_ctx(client);
	struct http_client_transport_quic_stream *st;
	int sock;

	sock = quic_stream_open(
		ctx->sock, QUIC_STREAM_CLIENT,
		bidirectional ? QUIC_STREAM_BIDIRECTIONAL : QUIC_STREAM_UNIDIRECTIONAL, 0);
	if (sock < 0) {
		NET_ERR("Failed to open QUIC stream, err %d", sock);
		return sock;
	}

	k_mutex_lock(&quic_lock, K_FOREVER);

	st = stream_slot_take(ctx, sock, !bidirectional);
	if (st != NULL) {
		quic_changed_locked(client);
	}

	k_mutex_unlock(&quic_lock);

	if (st == NULL) {
		NET_ERR("No free QUIC stream slot");
		(void)quic_stream_close(sock);
		return -ENOMEM;
	}

	*stream = st;

	return 0;
}

static void quic_transport_stream_close(struct http_client *client, void *stream, uint64_t error)
{
	struct http_client_transport_quic_stream *st = stream;

	k_mutex_lock(&quic_lock, K_FOREVER);

	if (st->sock >= 0) {
		/* Sent in STOP_SENDING when the peer has not finished yet. */
		(void)zsock_setsockopt(st->sock, ZSOCK_SOL_QUIC, ZSOCK_QUIC_SO_STOP_SENDING_CODE,
				       &error, sizeof(error));
		stream_slot_close(st);
		quic_changed_locked(client);
	}

	k_mutex_unlock(&quic_lock);
}

static int quic_transport_stream_id(struct http_client *client, void *stream, uint64_t *id)
{
	struct http_client_transport_quic_stream *st = stream;

	ARG_UNUSED(client);

	return quic_stream_get_id(st->sock, id);
}

static int quic_transport_send(struct http_client *client, void *stream, const uint8_t *data,
			       size_t len, bool end_stream)
{
	struct http_client_transport_quic_stream *st = stream;
	int ret;

	ARG_UNUSED(client);

	if (st == NULL || st->sock < 0) {
		return -EBADF;
	}

	if (len > 0) {
		ret = zsock_send_all(st->sock, data, len, 0,
				     K_MSEC(CONFIG_HTTP_CLIENT_SEND_TIMEOUT), NULL);
		if (ret < 0) {
			NET_ERR("Failed to send, err %d", ret);
			return ret;
		}
	}

	if (end_stream && zsock_shutdown(st->sock, ZSOCK_SHUT_WR) < 0) {
		ret = -errno;
		NET_ERR("Failed to end the stream, err %d", ret);
		return ret;
	}

	return 0;
}

/* Accept the streams the server opened. Returns -ENOTCONN once the
 * connection is closed. Must be called with quic_lock held.
 */
static int quic_accept_streams(struct http_client *client)
{
	struct http_client_transport_quic_ctx *ctx = quic_ctx(client);
	bool changed = false;
	int ret = 0;

	while (true) {
		struct zsock_pollfd pfd = {.fd = ctx->sock, .events = ZSOCK_POLLIN};
		int sock;

		if (zsock_poll(&pfd, 1, 0) <= 0 || (pfd.revents & ZSOCK_POLLIN) == 0) {
			break;
		}

		/* Accept blocks on a closed connection, which polls as
		 * readable as well.
		 */
		if ((pfd.revents & (ZSOCK_POLLHUP | ZSOCK_POLLERR | ZSOCK_POLLNVAL)) != 0) {
			ret = -ENOTCONN;
			break;
		}

		sock = zsock_accept(ctx->sock, NULL, NULL);
		if (sock < 0) {
			break;
		}

		if (stream_slot_take(ctx, sock, false) == NULL) {
			/* shortcut: a stream beyond the slots is refused unread,
			 * raise CONFIG_HTTP_CLIENT_HTTP3_PEER_UNI_STREAMS if a
			 * server opens more.
			 */
			NET_WARN("No free slot for a server stream, refused");
			(void)quic_stream_close(sock);
			continue;
		}

		NET_DBG("Accepted stream socket %d", sock);
		changed = true;
	}

	if (changed) {
		quic_changed_locked(client);
	}

	return ret;
}

static int quic_stream_recv(struct http_client *client,
			    struct http_client_transport_quic_stream *st, uint8_t *buf,
			    size_t bufsize, bool *end_stream)
{
	int ret;

	ret = zsock_recv(st->sock, buf, bufsize, ZSOCK_MSG_DONTWAIT);
	if (ret < 0) {
		return -errno;
	}

	if (ret == 0) {
		/* The end of the stream is reported once; then it is not
		 * polled any more.
		 */
		st->eof = true;
		*end_stream = true;
		quic_changed_locked(client);
	}

	return ret;
}

static int quic_transport_recv(struct http_client *client, void **stream, uint8_t *buf,
			       size_t bufsize, bool *end_stream)
{
	struct http_client_transport_quic_ctx *ctx = quic_ctx(client);
	struct http_client_transport_quic_stream *st = *stream;
	int ret = -EAGAIN;

	*end_stream = false;

	k_mutex_lock(&quic_lock, K_FOREVER);

	if (st != NULL) {
		if (stream_is_polled(st)) {
			ret = quic_stream_recv(client, st, buf, bufsize, end_stream);
		}

		goto out;
	}

	if (quic_accept_streams(client) < 0) {
		/* Closed by the peer. */
		ret = 0;
		goto out;
	}

	ARRAY_FOR_EACH(ctx->streams, i) {
		struct zsock_pollfd pfd;

		st = &ctx->streams[i];
		if (!stream_is_polled(st)) {
			continue;
		}

		pfd.fd = st->sock;
		pfd.events = ZSOCK_POLLIN;
		pfd.revents = 0;

		if (zsock_poll(&pfd, 1, 0) <= 0) {
			continue;
		}

		ret = quic_stream_recv(client, st, buf, bufsize, end_stream);
		if (ret != -EAGAIN) {
			*stream = st;
			break;
		}
	}

out:
	k_mutex_unlock(&quic_lock);

	if (ret < 0 && ret != -EAGAIN) {
		NET_ERR("Failed to receive, err %d", ret);
	}

	return ret;
}

static int quic_transport_wait(struct http_client *client, k_timeout_t timeout)
{
	struct http_client_transport_quic_ctx *ctx = quic_ctx(client);
	struct zsock_pollfd fds[QUIC_FDS_PER_CLIENT];
	int timeout_ms =
		K_TIMEOUT_EQ(timeout, K_FOREVER) ? -1 : (int)k_ticks_to_ms_ceil32(timeout.ticks);
	int nfds = 0;
	int ret;

	if (ctx->sock < 0) {
		return -ENOTCONN;
	}

	k_mutex_lock(&quic_lock, K_FOREVER);

	fds[nfds].fd = ctx->sock;
	fds[nfds].events = ZSOCK_POLLIN;
	nfds++;

	ARRAY_FOR_EACH(ctx->streams, i) {
		if (stream_is_polled(&ctx->streams[i])) {
			fds[nfds].fd = ctx->streams[i].sock;
			fds[nfds].events = ZSOCK_POLLIN;
			nfds++;
		}
	}

	k_mutex_unlock(&quic_lock);

	ret = zsock_poll(fds, nfds, timeout_ms);
	if (ret < 0) {
		return -errno;
	}

	if (ret == 0) {
		return -EAGAIN;
	}

	for (int i = 0; i < nfds; i++) {
		if (fds[i].revents != 0) {
			ret = quic_revents_status(fds[i].fd, fds[i].revents);
			if (ret < 0) {
				return ret;
			}
		}
	}

	return 0;
}

static void quic_transport_stop(struct http_client *client)
{
	quic_unregister(client);
}

static int quic_transport_close(struct http_client *client)
{
	struct http_client_transport_quic_ctx *ctx = quic_ctx(client);
	int ret;

	quic_unregister(client);
	quic_wait_notified(client);

	k_mutex_lock(&quic_lock, K_FOREVER);

	ARRAY_FOR_EACH(ctx->streams, i) {
		if (ctx->streams[i].sock >= 0) {
			stream_slot_close(&ctx->streams[i]);
		}
	}

	k_mutex_unlock(&quic_lock);

	NET_DBG("Closing QUIC connection %d", ctx->sock);

	ret = quic_connection_close(ctx->sock);
	ctx->sock = INVALID_SOCK;

	return ret;
}

static const struct http_client_transport_ops http_transport_quic = {
	.secure = true,
	.init = quic_transport_init,
	.connect = quic_transport_connect,
	.send = quic_transport_send,
	.recv = quic_transport_recv,
	.wait = quic_transport_wait,
	.stop = quic_transport_stop,
	.close = quic_transport_close,
	.stream_open = quic_transport_stream_open,
	.stream_close = quic_transport_stream_close,
	.stream_id = quic_transport_stream_id,
};

int http_client_init_quic(struct http_client *client,
			  struct http_client_transport_quic_ctx *transport_ctx)
{
	if (transport_ctx == NULL) {
		return -EINVAL;
	}

	return http_client_init(client, HTTP_CLIENT_VERSION_3, &http_transport_quic, transport_ctx);
}
