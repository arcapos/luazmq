/*
 * Copyright (c) 2014 - 2020 Micro Systems Marc Balmer, CH-5073 Gipf-Oberfrick.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Micro Systems Marc Balmer nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* 0MQ for Lua */

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <string.h>
#include <stdlib.h>
#include <zmq.h>

#include "luazmq.h"

/* Creating a new context and context methods */
static int
luazmq_ctx_new(lua_State *L)
{
	void **ctx;

	ctx = lua_newuserdata(L, sizeof(void *));
	*ctx = zmq_ctx_new();
	luaL_getmetatable(L, ZMQ_CTX_METATABLE);
	lua_setmetatable(L, -2);
	return 1;
}

static int ctx_get_option_names[] = {
	ZMQ_IO_THREADS,
	ZMQ_MAX_SOCKETS,
	ZMQ_MAX_MSGSZ,
	ZMQ_SOCKET_LIMIT,
	ZMQ_IPV6,
	ZMQ_BLOCKY,
	ZMQ_MSG_T_SIZE
};

static const char *ctx_get_options[] = {
	"io-threads",
	"max-sockets",
	"max-msgsz",
	"socket-limit",
	"ipv6",
	"blocky",
	"msg-t-size",
	NULL
};

static int
luazmq_ctx_get(lua_State *L)
{
	void **ctx;
	int option_name, option_value;

	ctx = luaL_checkudata(L, 1, ZMQ_CTX_METATABLE);
	option_name = ctx_get_option_names[
	    luaL_checkoption(L, 2, NULL, ctx_get_options)];
	if ((option_value = zmq_ctx_get(*ctx, option_name)) == -1)
		return luaL_error(L, "zmq_ctx_get failed");
	lua_pushinteger(L, option_value);
	return 1;
}

static int ctx_set_option_names[] = {
	ZMQ_IO_THREADS,
	ZMQ_THREAD_SCHED_POLICY,
	ZMQ_THREAD_PRIORITY,
	ZMQ_MAX_SOCKETS,
	ZMQ_MAX_MSGSZ,
	ZMQ_IPV6,
	ZMQ_BLOCKY,
};

static const char *ctx_set_options[] = {
	"io-threads",
	"thread-sched-policy",
	"thread-priority",
	"max-sockets",
	"max-msgsz",
	"ipv6",
	"blocky",
	NULL
};

static int
luazmq_ctx_set(lua_State *L)
{
	void **ctx;
	int option_name, option_value;

	ctx = luaL_checkudata(L, 1, ZMQ_CTX_METATABLE);
	option_name = ctx_set_option_names[
	    luaL_checkoption(L, 2, NULL, ctx_set_options)];
	option_value = luaL_checkinteger(L, 3);
	if (zmq_ctx_set(*ctx, option_name, option_value))
		lua_pushnil(L);
	else
		lua_pushboolean(L, 1);
	return 1;
}

static int
luazmq_ctx_shutdown(lua_State *L)
{
	void **ctx;

	ctx = luaL_checkudata(L, -1, ZMQ_CTX_METATABLE);
	if (*ctx)
		zmq_ctx_shutdown(*ctx);
	return 0;
}

static int socket_types[] = {
	ZMQ_PUB,
	ZMQ_SUB,
	ZMQ_XPUB,
	ZMQ_XSUB,
	ZMQ_PUSH,
	ZMQ_PULL,
	ZMQ_PAIR,
	ZMQ_STREAM,
	ZMQ_REQ,
	ZMQ_REP,
	ZMQ_DEALER,
	ZMQ_ROUTER
};

static const char *socket_type_nm[] = {
	"pub",
	"sub",
	"xpub",
	"xsub",
	"push",
	"pull",
	"pair",
	"stream",
	"req",
	"rep",
	"dealer",
	"router",
	NULL
};

static int
luazmq_ctx_socket(lua_State *L)
{
	void **sock, **ctx;

	ctx = luaL_checkudata(L, 1, ZMQ_CTX_METATABLE);

	sock = lua_newuserdata(L, sizeof(void *));
	*sock = zmq_socket(*ctx,
	    socket_types[luaL_checkoption(L, 2, NULL, socket_type_nm)]);
	luaL_getmetatable(L, ZMQ_SOCKET_METATABLE);
	lua_setmetatable(L, -2);
	return 1;
}

static int
luazmq_ctx_term(lua_State *L)
{
	void **ctx;

	ctx = luaL_checkudata(L, -1, ZMQ_CTX_METATABLE);
	if (*ctx) {
		zmq_ctx_term(*ctx);
		*ctx = NULL;
	}
	return 0;
}

static int
luazmq_strerror(lua_State *L)
{
	lua_pushstring(L, zmq_strerror(errno));
	return 1;
}

static int
luazmq_curve_keypair(lua_State *L)
{
	char z85_public_key[41], z85_secret_key[41];

	if (zmq_curve_keypair(z85_public_key, z85_secret_key))
		return luaL_error(L, "libzmq was not built with cryptopgraphic "
		    "support");

	lua_pushstring(L, z85_public_key);
	lua_pushstring(L, z85_secret_key);
	return 2;
}

static int
luazmq_version(lua_State *L)
{
	int major, minor, patch;
	zmq_version(&major, &minor, &patch);
	lua_newtable(L);
	lua_pushinteger(L, major);
	lua_setfield(L, -2, "major");
	lua_pushinteger(L, minor);
	lua_setfield(L, -2, "minor");
	lua_pushinteger(L, patch);
	lua_setfield(L, -2, "patch");
	return 1;
}

static int
luazmq_z85_decode(lua_State *L)
{
	char *string;
	size_t len;
	uint8_t *dest;

	string = (char *)luaL_checklstring(L, 1, &len);

	dest = malloc(0.8 * len);
	if (dest == NULL)
		return luaL_error(L, "memory error");
	if (zmq_z85_decode(dest, string) == NULL)
		lua_pushnil(L);
	else
		lua_pushstring(L, (const char *)dest);
	free(dest);
	return 1;
}

static int
luazmq_z85_encode(lua_State *L)
{
	char *dest;
	uint8_t *data;
	size_t size;

	data = (uint8_t *)luaL_checklstring(L, 1, &size);

	dest = malloc(size * 1.25 + 1);
	if (dest == NULL)
		return luaL_error(L, "memory error");
	if (zmq_z85_encode(dest, data, size) == NULL)
		lua_pushnil(L);
	else
		lua_pushstring(L, dest);
	free(dest);
	return 1;
}

static int
luazmq_bind(lua_State *L)
{
	void **sock;

	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);
	if (zmq_bind(*sock, luaL_checkstring(L, 2)))
		lua_pushnil(L);
	else
		lua_pushboolean(L, 1);
	return 1;
}

static int
luazmq_close(lua_State *L)
{
	void **sock;

	sock = luaL_checkudata(L, -1, ZMQ_SOCKET_METATABLE);
	if (*sock) {
		zmq_close(*sock);
		*sock = NULL;
	}
	return 0;
}


static int
luazmq_connect(lua_State *L)
{
	void **sock;

	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);
	if (zmq_connect(*sock, luaL_checkstring(L, 2)))
		lua_pushnil(L);
	else
		lua_pushboolean(L, 1);
	return 1;
}

static int getsockopt_option_names[] = {
	ZMQ_AFFINITY,
	ZMQ_BACKLOG,
	ZMQ_BINDTODEVICE,
	ZMQ_CONNECT_TIMEOUT,
	ZMQ_CURVE_PUBLICKEY,
	ZMQ_CURVE_SECRETKEY,
	ZMQ_CURVE_SERVERKEY,
	ZMQ_EVENTS,
	ZMQ_FD,
	ZMQ_GSSAPI_PLAINTEXT,
	ZMQ_GSSAPI_PRINCIPAL,
	ZMQ_GSSAPI_SERVER,
	ZMQ_GSSAPI_SERVICE_PRINCIPAL,
	ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE,
	ZMQ_GSSAPI_PRINCIPAL_NAMETYPE,
	ZMQ_HANDSHAKE_IVL,
	ZMQ_IDENTITY,
	ZMQ_IMMEDIATE,
	ZMQ_INVERT_MATCHING,
	ZMQ_IPV4ONLY,
	ZMQ_IPV6,
	ZMQ_LAST_ENDPOINT,
	ZMQ_LINGER,
	ZMQ_MAXMSGSIZE,
	ZMQ_MECHANISM,
	ZMQ_MULTICAST_HOPS,
	ZMQ_MULTICAST_MAXTPDU,
	ZMQ_PLAIN_PASSWORD,
	ZMQ_PLAIN_SERVER,
	ZMQ_PLAIN_USERNAME,
	ZMQ_USE_FD,
	ZMQ_RATE,
	ZMQ_RCVBUF,
	ZMQ_RCVHWM,
	ZMQ_RCVMORE,
	ZMQ_RCVTIMEO,
	ZMQ_RECONNECT_IVL,
	ZMQ_RECONNECT_IVL_MAX,
	ZMQ_RECOVERY_IVL,
	ZMQ_SNDBUF,
	ZMQ_SNDHWM,
	ZMQ_SNDTIMEO,
	ZMQ_SOCKS_PROXY,
	ZMQ_TCP_KEEPALIVE,
	ZMQ_TCP_KEEPALIVE_CNT,
	ZMQ_TCP_KEEPALIVE_IDLE,
	ZMQ_TCP_KEEPALIVE_INTVL,
	ZMQ_TCP_MAXRT,
	ZMQ_THREAD_SAFE,
	ZMQ_TOS,
	ZMQ_TYPE,
	ZMQ_ZAP_DOMAIN,
	ZMQ_VMCI_BUFFER_SIZE,
	ZMQ_VMCI_BUFFER_MIN_SIZE,
	ZMQ_VMCI_BUFFER_MAX_SIZE,
	ZMQ_VMCI_CONNECT_TIMEOUT
};

static const char *getsockopt_options[] = {
	"affinity",
	"backlog",
	"bindtodevice",
	"connect-timeout",
	"curve-publickey",
	"curve-secretkey",
	"curve-serverkey",
	"events",
	"fd",
	"gssapi-plaintext",
	"gssapi-principal",
	"gssapi-server",
	"gssapi-service-principal",
	"gssapi-service-principal-nametype",
	"gssapi-principal-nametype",
	"handshake-ivl",
	"identity",
	"immediate",
	"invert-matching",
	"ipv4only",
	"ipv6",
	"last-endpoint",
	"linger",
	"maxmsgsize",
	"mechanism",
	"multicast-hops",
	"multicast-maxtpdu",
	"plain-password",
	"plain-server",
	"plain-username",
	"use-fd",
	"rate",
	"rcvbuf",
	"rcvhwm",
	"rcvmore",
	"rcvtimeo",
	"reconnect-ivl",
	"reconnect-ivl-max",
	"recovery-ivl",
	"sndbuf",
	"sndhwm",
	"sndtimeo",
	"socks-proxy",
	"tcp-keepalive",
	"tcp-keepalive-cnt",
	"tcp-keepalive-idle",
	"tcp-keepalive-intvl",
	"tcp-maxrt",
	"thread-safe",
	"tos",
	"type",
	"zap-domain",
	"vmci-buffer-size",
	"vmci-buffer-min-size",
	"vmci-buffer-max-size",
	"vmci-connect-timeout",
	NULL
};

#define OPTSIZ	1024

static int
luazmq_getsockopt(lua_State *L)
{
	void **sock;
	int option_name;
	uint8_t option_value[OPTSIZ];
	size_t len;

	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);
	option_name = getsockopt_option_names[luaL_checkoption(L, 2, NULL,
	    getsockopt_options)];
	len = sizeof option_value;
	if (zmq_getsockopt(*sock, option_name, option_value, &len))
		return luaL_error(L, "zmq_getsockopt failed");

	switch (option_name) {
	/* options returning boolean */
	case ZMQ_GSSAPI_PLAINTEXT:
	case ZMQ_GSSAPI_SERVER:
	case ZMQ_IMMEDIATE:
	case ZMQ_IPV4ONLY:
	case ZMQ_IPV6:
	case ZMQ_THREAD_SAFE:
		lua_pushboolean(L, (int)(*(int *)&option_value[0]));
		break;

	/* options returning int */
	case ZMQ_BACKLOG:
	case ZMQ_CONNECT_TIMEOUT:
	case ZMQ_FD:
	case ZMQ_HANDSHAKE_IVL:
	case ZMQ_INVERT_MATCHING:
	case ZMQ_LINGER:
	case ZMQ_MULTICAST_HOPS:
	case ZMQ_MULTICAST_MAXTPDU:
	case ZMQ_PLAIN_SERVER:
	case ZMQ_USE_FD:
	case ZMQ_RATE:
	case ZMQ_RCVBUF:
	case ZMQ_RCVHWM:
	case ZMQ_RCVMORE:
	case ZMQ_RCVTIMEO:
	case ZMQ_RECONNECT_IVL:
	case ZMQ_RECONNECT_IVL_MAX:
	case ZMQ_RECOVERY_IVL:
	case ZMQ_SNDBUF:
	case ZMQ_SNDHWM:
	case ZMQ_SNDTIMEO:
	case ZMQ_TCP_KEEPALIVE:
	case ZMQ_TCP_KEEPALIVE_CNT:
	case ZMQ_TCP_KEEPALIVE_IDLE:
	case ZMQ_TCP_KEEPALIVE_INTVL:
	case ZMQ_TCP_MAXRT:
	case ZMQ_TOS:
	case ZMQ_TYPE:
	case ZMQ_VMCI_CONNECT_TIMEOUT:
		lua_pushinteger(L, (lua_Integer)(*(int *)&option_value[0]));
		break;

	/* options returning int64_t */
	case ZMQ_MAXMSGSIZE:
		lua_pushinteger(L, (lua_Integer)(*(int64_t *)&option_value[0]));
		break;

	/* options returning uint64_t */
	case ZMQ_AFFINITY:
	case ZMQ_VMCI_BUFFER_SIZE:
	case ZMQ_VMCI_BUFFER_MIN_SIZE:
	case ZMQ_VMCI_BUFFER_MAX_SIZE:
		lua_pushinteger(L,
		    (lua_Integer)(*(uint64_t *)&option_value[0]));
		break;

	/* options returning string or binary data */
	case ZMQ_BINDTODEVICE:
	case ZMQ_CURVE_PUBLICKEY:
	case ZMQ_CURVE_SECRETKEY:
	case ZMQ_CURVE_SERVERKEY:
	case ZMQ_GSSAPI_PRINCIPAL:
	case ZMQ_GSSAPI_SERVICE_PRINCIPAL:
	case ZMQ_IDENTITY:
	case ZMQ_LAST_ENDPOINT:
	case ZMQ_PLAIN_PASSWORD:
	case ZMQ_PLAIN_USERNAME:
	case ZMQ_SOCKS_PROXY:
	case ZMQ_ZAP_DOMAIN:
		lua_pushlstring(L, option_value, len);
		break;

	/* options returning a table, containing one or more strings */
	case ZMQ_EVENTS:
		lua_newtable(L);
		if (*(int *)&option_value & ZMQ_POLLIN) {
			lua_pushstring(L, "pollin");
			lua_pushboolean(L, 1);
			lua_settable(L, -3);
		}
		if (*(int *)&option_value & ZMQ_POLLOUT) {
			lua_pushstring(L, "pollout");
			lua_pushboolean(L, 1);
			lua_settable(L, -3);
		}
		break;

	/* options returning int, mapped to string */
	case ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE:
	case ZMQ_GSSAPI_PRINCIPAL_NAMETYPE:
		switch (*(int *)&option_value) {
		case ZMQ_GSSAPI_NT_HOSTBASED:
			lua_pushstring(L, "hostbased");
			break;
		case ZMQ_GSSAPI_NT_USER_NAME:
			lua_pushstring(L, "user-name");
			break;
		case ZMQ_GSSAPI_NT_KRB5_PRINCIPAL:
			lua_pushstring(L, "krb5-principal");
			break;
		}
		break;
	case ZMQ_MECHANISM:
		switch (*(int *)&option_value) {
		case ZMQ_NULL:
			lua_pushstring(L, "null");
			break;
		case ZMQ_PLAIN:
			lua_pushstring(L, "plain");
			break;
		case ZMQ_CURVE:
			lua_pushstring(L, "curve");
			break;
		case ZMQ_GSSAPI:
			lua_pushstring(L, "gssapi");
			break;
		}
		break;
	}
	return 1;
}

static int msg_recv_flags[] = {
	ZMQ_DONTWAIT
};

static const char *msg_recv_options[] = {
	"dontwait",
	NULL
};

static int
luazmq_msg_recv(lua_State *L)
{
	zmq_msg_t msg;
	void **sock;
	size_t len;
	int flags;
	char *buf;

	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);
	flags = lua_gettop(L) == 2 ?
	    msg_recv_flags[luaL_checkoption(L, 2, NULL, msg_recv_options)] : 0;

	if (zmq_msg_init(&msg))
		return luaL_error(L, "zmq_msg_init failed");
	if (zmq_msg_recv(&msg, *sock, flags) == -1) {
		if (errno != EAGAIN)
			return luaL_error(L, "zmq_msg_recv failed");
		else {
			lua_pushnil(L);
			return 1;
		}
	}
	len = zmq_msg_size(&msg);
	buf = malloc(len + 1);
	memcpy(buf, zmq_msg_data(&msg), len);
	buf[len] = '\0';
	lua_pushlstring(L, buf, len);
	free(buf);
	zmq_msg_close(&msg);
	return 1;
}

static int msg_send_flags[] = {
	ZMQ_DONTWAIT,
	ZMQ_SNDMORE
};

static const char *msg_send_options[] = {
	"dontwait",
	"sndmore",
	NULL
};

static int
luazmq_msg_send(lua_State *L)
{
	zmq_msg_t msg;
	void **sock;
	size_t len;
	int n, flags;
	const char *buf;

	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);
	buf = luaL_checklstring(L, 2, &len);

	for (flags = 0, n = 3; n <= lua_gettop(L); n++)
		flags |= msg_send_flags[luaL_checkoption(L, n, NULL,
		    msg_send_options)];

	if (zmq_msg_init_size(&msg, len))
		return luaL_error(L, "zmq_msg_init failed");
	memcpy(zmq_msg_data(&msg), buf, len);
	if (zmq_msg_send(&msg, *sock, flags) == -1)
		return luaL_error(L, "zmq_msg_send failed");
	zmq_msg_close(&msg);
	return 0;
}

static int
luazmq_recv(lua_State *L)
{
	void **sock;
	int nbytes, flags;
	char *buf;
	size_t len;

	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);
	len = luaL_checkinteger(L, 2);
	flags = lua_gettop(L) == 3 ?
	     msg_recv_flags[luaL_checkoption(L, 3, NULL, msg_recv_options)] : 0;
	buf = malloc(len + 1);
	nbytes = zmq_recv(*sock, buf, len, flags);
	buf[len] = '\0';
	buf[nbytes] = '\0';
	lua_pushlstring(L, buf, nbytes);
	free(buf);
	return 1;
}

static int
luazmq_send(lua_State *L)
{
	void **sock;
	size_t len;
	int n, nbytes, flags;
	const char *buf;

	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);
	buf = lua_tolstring(L, 2, &len);

	for (flags = 0, n = 3; n <= lua_gettop(L); n++)
		flags |= msg_send_flags[luaL_checkoption(L, n, NULL,
		    msg_send_options)];

	nbytes = zmq_send(*sock, buf, len, flags);
	lua_pushinteger(L, nbytes);
	return 1;
}

static int setsockopt_option_names[] = {
	ZMQ_AFFINITY,
	ZMQ_BACKLOG,
	ZMQ_CONNECT_RID,
	ZMQ_CONFLATE,
	ZMQ_CONNECT_TIMEOUT,
	ZMQ_CURVE_PUBLICKEY,
	ZMQ_CURVE_SECRETKEY,
	ZMQ_CURVE_SERVER,
	ZMQ_CURVE_SERVERKEY,
	ZMQ_GSSAPI_PLAINTEXT,
	ZMQ_GSSAPI_PRINCIPAL,
	ZMQ_GSSAPI_SERVER,
	ZMQ_GSSAPI_SERVICE_PRINCIPAL,
	ZMQ_HANDSHAKE_IVL,
	ZMQ_HEARTBEAT_IVL,
	ZMQ_HEARTBEAT_TIMEOUT,
	ZMQ_HEARTBEAT_TTL,
	ZMQ_IDENTITY,
	ZMQ_IMMEDIATE,
	ZMQ_INVERT_MATCHING,
	ZMQ_IPV6,
	ZMQ_LINGER,
	ZMQ_MAXMSGSIZE,
	ZMQ_MULTICAST_HOPS,
	ZMQ_MULTICAST_MAXTPDU,
	ZMQ_PLAIN_PASSWORD,
	ZMQ_PLAIN_SERVER,
	ZMQ_PLAIN_USERNAME,
	ZMQ_USE_FD,
	ZMQ_PROBE_ROUTER,
	ZMQ_RATE,
	ZMQ_RCVBUF,
	ZMQ_RCVHWM,
	ZMQ_RCVTIMEO,
	ZMQ_RECONNECT_IVL,
	ZMQ_RECONNECT_IVL_MAX,
	ZMQ_RECOVERY_IVL,
	ZMQ_REQ_CORRELATE,
	ZMQ_REQ_RELAXED,
	ZMQ_ROUTER_HANDOVER,
	ZMQ_ROUTER_MANDATORY,
	ZMQ_ROUTER_RAW,
	ZMQ_SNDBUF,
	ZMQ_SNDHWM,
	ZMQ_SNDTIMEO,
	ZMQ_SOCKS_PROXY,
	ZMQ_STREAM_NOTIFY,
	ZMQ_SUBSCRIBE,
	ZMQ_TCP_KEEPALIVE,
	ZMQ_TCP_KEEPALIVE_CNT,
	ZMQ_TCP_KEEPALIVE_IDLE,
	ZMQ_TCP_KEEPALIVE_INTVL,
	ZMQ_TCP_MAXRT,
	ZMQ_TOS,
	ZMQ_UNSUBSCRIBE,
	ZMQ_XPUB_VERBOSE,
	ZMQ_XPUB_VERBOSER,
	ZMQ_XPUB_MANUAL,
	ZMQ_XPUB_NODROP,
	ZMQ_XPUB_WELCOME_MSG,
	ZMQ_ZAP_DOMAIN,
	ZMQ_IPV4ONLY,
	ZMQ_VMCI_BUFFER_SIZE,
	ZMQ_VMCI_BUFFER_MIN_SIZE,
	ZMQ_VMCI_BUFFER_MAX_SIZE,
	ZMQ_VMCI_CONNECT_TIMEOUT
};

static const char *setsockopt_options[] = {
	"affinity",
	"backlog",
	"connect-rid",
	"conflate",
	"connect-timeout",
	"curve-publickey",
	"curve-secretkey",
	"curve-server",
	"curve-serverkey",
	"gssapi-plaintext",
	"gssapi-principal",
	"gssapi-server",
	"gssapi-service-principal",
	"handshake-ivl",
	"heartbeat-ivl",
	"heartbeat-timeout",
	"heartbeat-ttl",
	"identity",
	"immediate",
	"invert-matching",
	"ipv6",
	"linger",
	"maxmsgsize",
	"multicast-hops",
	"multicast-maxtpdu",
	"plain-password",
	"plain-server",
	"plain-username",
	"use-fd",
	"probe-router",
	"rate",
	"rcvbuf",
	"rcvhwm",
	"rcvtimeo",
	"reconnect-ivl",
	"reconnect-ivl-max",
	"recovery-ivl",
	"req-correlate",
	"req-relaxed",
	"router-handover",
	"router-mandatory",
	"router-raw",
	"sndbuf",
	"sndhwm",
	"sndtimeo",
	"socks-proxy",
	"stream-notify",
	"subscribe",
	"tcp-keepalive",
	"tcp-keepalive-cnt",
	"tcp-keepalive-idle",
	"tcp-keepalive-intvl",
	"tcp-maxrt",
	"tos",
	"ubsubscribe",
	"xpub-verbose",
	"xpub-verboser",
	"xpub-manual",
	"xpub-nodrop",
	"xpub-welcome-msg",
	"zap-domain",
	"ipv4only",
	"vmci-buffer-size",
	"vmci-buffer-min-size",
	"vmci-buffer-max-size",
	"vmci-connect-timeout",
	NULL
};

static int
luazmq_setsockopt(lua_State *L)
{
	void **sock;
	size_t len;
	int option_name, rv, intval;
	const char *strval;
	int64_t int64_tval;
	uint64_t uint64_tval;

	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);
	option_name = setsockopt_option_names[luaL_checkoption(L, 2, NULL,
	    setsockopt_options)];

	switch (option_name) {
	/* options using a boolean */
	case ZMQ_CONFLATE:
	case ZMQ_IMMEDIATE:
	case ZMQ_IPV6:
		intval = lua_toboolean(L, 3);
		rv = zmq_setsockopt(*sock, option_name, &intval, sizeof intval);
		break;

	/* options using an int */
	case ZMQ_BACKLOG:
	case ZMQ_CONNECT_TIMEOUT:
	case ZMQ_CURVE_SERVER:
	case ZMQ_GSSAPI_PLAINTEXT:
	case ZMQ_GSSAPI_SERVER:
	case ZMQ_HANDSHAKE_IVL:
	case ZMQ_HEARTBEAT_IVL:
	case ZMQ_HEARTBEAT_TIMEOUT:
	case ZMQ_HEARTBEAT_TTL:
	case ZMQ_INVERT_MATCHING:
	case ZMQ_LINGER:
	case ZMQ_MULTICAST_HOPS:
	case ZMQ_MULTICAST_MAXTPDU:
	case ZMQ_PLAIN_SERVER:
	case ZMQ_USE_FD:
	case ZMQ_PROBE_ROUTER:
	case ZMQ_RATE:
	case ZMQ_RCVBUF:
	case ZMQ_RCVHWM:
	case ZMQ_RCVTIMEO:
	case ZMQ_RECONNECT_IVL:
	case ZMQ_RECONNECT_IVL_MAX:
	case ZMQ_RECOVERY_IVL:
	case ZMQ_REQ_CORRELATE:
	case ZMQ_REQ_RELAXED:
	case ZMQ_ROUTER_HANDOVER:
	case ZMQ_ROUTER_MANDATORY:
	case ZMQ_ROUTER_RAW:
	case ZMQ_SNDBUF:
	case ZMQ_SNDHWM:
	case ZMQ_SNDTIMEO:
	case ZMQ_STREAM_NOTIFY:
	case ZMQ_TCP_KEEPALIVE:
	case ZMQ_TCP_KEEPALIVE_CNT:
	case ZMQ_TCP_KEEPALIVE_IDLE:
	case ZMQ_TCP_KEEPALIVE_INTVL:
	case ZMQ_TCP_MAXRT:
	case ZMQ_TOS:
	case ZMQ_XPUB_VERBOSE:
	case ZMQ_XPUB_VERBOSER:
	case ZMQ_XPUB_MANUAL:
	case ZMQ_XPUB_NODROP:
	case ZMQ_IPV4ONLY:
	case ZMQ_VMCI_CONNECT_TIMEOUT:
		intval = luaL_checkinteger(L, 3);
		rv = zmq_setsockopt(*sock, option_name, &intval, sizeof intval);
		break;

	/* options using an int64_t */
	case ZMQ_MAXMSGSIZE:
		int64_tval = luaL_checkinteger(L, 3);
		rv = zmq_setsockopt(*sock, option_name, &int64_tval,
		    sizeof int64_tval);
		break;

	/* options using an uint64_t */
	case ZMQ_AFFINITY:
	case ZMQ_VMCI_BUFFER_SIZE:
	case ZMQ_VMCI_BUFFER_MIN_SIZE:
	case ZMQ_VMCI_BUFFER_MAX_SIZE:
		uint64_tval = luaL_checkinteger(L, 3);
		rv = zmq_setsockopt(*sock, option_name, &uint64_tval,
		    sizeof uint64_tval);
		break;

	/* options using a string or binary data */
	case ZMQ_CONNECT_RID:
	case ZMQ_CURVE_PUBLICKEY:
	case ZMQ_CURVE_SECRETKEY:
	case ZMQ_CURVE_SERVERKEY:
	case ZMQ_GSSAPI_PRINCIPAL:
	case ZMQ_GSSAPI_SERVICE_PRINCIPAL:
	case ZMQ_IDENTITY:
	case ZMQ_PLAIN_PASSWORD:
	case ZMQ_PLAIN_USERNAME:
	case ZMQ_SOCKS_PROXY:
	case ZMQ_SUBSCRIBE:
	case ZMQ_UNSUBSCRIBE:
	case ZMQ_XPUB_WELCOME_MSG:
	case ZMQ_ZAP_DOMAIN:
		strval = luaL_checklstring(L, 3, &len);
		rv = zmq_setsockopt(*sock, option_name, strval, len);
		break;
	}
	lua_pushboolean(L, rv == 0 ? 1 : 0);
	return 1;
}

static int
luazmq_unbind(lua_State *L)
{
	void **sock;

	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);

	if (zmq_unbind(*sock, luaL_checkstring(L, 2)))
		lua_pushnil(L);
	else
		lua_pushboolean(L, 1);
	return 1;
}

int
luaopen_zmq(lua_State *L)
{
	struct luaL_Reg functions[] = {
		{ "ctxNew",		luazmq_ctx_new },
		{ "curveKeypair",	luazmq_curve_keypair },
		{ "strerror",		luazmq_strerror },
		{ "version",		luazmq_version },
		{ "z85Decode",		luazmq_z85_decode },
		{ "z85Encode",		luazmq_z85_encode },
		{ NULL,			NULL }
	};
	struct luaL_Reg ctx_methods[] = {
		{ "get",		luazmq_ctx_get },
		{ "set",		luazmq_ctx_set },
		{ "shutdown",		luazmq_ctx_shutdown },
		{ "socket",		luazmq_ctx_socket },
		{ "term",		luazmq_ctx_term },
		{ NULL,			NULL }
	};
	struct luaL_Reg socket_methods[] = {
		{ "bind",		luazmq_bind },
		{ "close",		luazmq_close },
		{ "connect",		luazmq_connect },
		{ "getsockopt",		luazmq_getsockopt },
		{ "msgRecv",		luazmq_msg_recv },
		{ "msgSend",		luazmq_msg_send },
		{ "recv",		luazmq_recv },
		{ "send",		luazmq_send },
		{ "setsockopt",		luazmq_setsockopt },
		{ "unbind",		luazmq_unbind },
		{ NULL,			NULL }
	};
	int n;

	luaL_newlib(L, functions);
	if (luaL_newmetatable(L, ZMQ_CTX_METATABLE)) {
		luaL_setfuncs(L, ctx_methods, 0);
		lua_pushliteral(L, "__gc");
		lua_pushcfunction(L, luazmq_ctx_term);
		lua_settable(L, -3);

		lua_pushliteral(L, "__index");
		lua_pushvalue(L, -2);
		lua_settable(L, -3);

		lua_pushliteral(L, "__metatable");
		lua_pushliteral(L, "must not access this metatable");
		lua_settable(L, -3);
	}
	lua_pop(L, 1);

	if (luaL_newmetatable(L, ZMQ_SOCKET_METATABLE)) {
		luaL_setfuncs(L, socket_methods, 0);
		lua_pushliteral(L, "__gc");
		lua_pushcfunction(L, luazmq_close);
		lua_settable(L, -3);

		lua_pushliteral(L, "__index");
		lua_pushvalue(L, -2);
		lua_settable(L, -3);

		lua_pushliteral(L, "__metatable");
		lua_pushliteral(L, "must not access this metatable");
		lua_settable(L, -3);
	}
	lua_pop(L, 1);

	lua_pushliteral(L, "_COPYRIGHT");
	lua_pushliteral(L, "Copyright (C) 2014 - 2020 by "
	    "micro systems marc balmer");
	lua_settable(L, -3);
	lua_pushliteral(L, "_DESCRIPTION");
	lua_pushliteral(L, "0MQ for Lua");
	lua_settable(L, -3);
	lua_pushliteral(L, "_VERSION");
	lua_pushliteral(L, "zmq 1.2.1");
	lua_settable(L, -3);
	return 1;
}
