/*
 * Copyright (c) 2014 - 2019 Micro Systems Marc Balmer, CH-5073 Gipf-Oberfrick.
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

/* The single per-process 0MQ context */
void *zmq_context;

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

/* XXX handles only integers atm */
static int
luazmq_ctx_get(lua_State *L)
{
	void **ctx;
	int option_name;
	int option_value;

	ctx = luaL_checkudata(L, 1, ZMQ_CTX_METATABLE);
	option_name = luaL_checkinteger(L, 2);
	if ((option_value = zmq_ctx_get(*ctx, option_name)) == -1)
		return luaL_error(L, "zmq_ctx_get failed");
	lua_pushinteger(L, option_value);
	return 1;
}

static int
luazmq_ctx_set(lua_State *L)
{
	void **ctx;
	int option_name, option_value;

	ctx = luaL_checkudata(L, 1, ZMQ_CTX_METATABLE);
	option_name = luaL_checkinteger(L, 2);
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

static int
luazmq_ctx_socket(lua_State *L)
{
	void **sock;
	void **ctx;

	ctx = luaL_checkudata(L, 1, ZMQ_CTX_METATABLE);

	sock = lua_newuserdata(L, sizeof(void *));
	*sock = zmq_socket(*ctx, luaL_checkinteger(L, -2));
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
luazmq_socket(lua_State *L)
{
	void **sock;

	sock = lua_newuserdata(L, sizeof(void *));
	*sock = zmq_socket(zmq_context, luaL_checkinteger(L, -2));
	luaL_getmetatable(L, ZMQ_SOCKET_METATABLE);
	lua_setmetatable(L, -2);
	return 1;
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
	lua_pushinteger(L, major);
	lua_pushinteger(L, minor);
	lua_pushinteger(L, patch);
	return 3;
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

	data = (uint8_t *)luaL_checkstring(L, 1);
	size = luaL_checkinteger(L, 2);

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

/* XXX handles only integers atm */
static int
luazmq_getsockopt(lua_State *L)
{
	void **sock;
	int option_name;
	int option_value;
	size_t len;

	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);
	option_name = luaL_checkinteger(L, 2);
	len = sizeof option_value;
	if (zmq_getsockopt(*sock, option_name, &option_value, &len))
		return luaL_error(L, "zmq_getsockopt failed");
	lua_pushinteger(L, option_value);
	return 1;
}

static int
luazmq_msg_recv(lua_State *L)
{
	zmq_msg_t msg;
	void **sock;
	size_t len;
	int flags;
	char *buf;

	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);
	flags = lua_gettop(L) == 2 ? lua_tointeger(L, 2) : 0;

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
	lua_pushstring(L, buf);
	lua_pushnumber(L, len);
	free(buf);
	zmq_msg_close(&msg);
	return 2;
}

static int
luazmq_msg_send(lua_State *L)
{
	zmq_msg_t msg;
	void **sock;
	size_t len;
	int flags;
	const char *buf;

	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);
	flags = lua_gettop(L) == 3 ? lua_tointeger(L, 3) : 0;

	buf = luaL_checklstring(L, 2, &len);

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
	flags = lua_gettop(L) == 3 ? lua_tointeger(L, 3) : 0;
	buf = malloc(len + 1);
	nbytes = zmq_recv(*sock, buf, len, flags);
	buf[len] = '\0';
	buf[nbytes] = '\0';
	lua_pushstring(L, buf);
	lua_pushinteger(L, nbytes);
	free(buf);
	return 2;
}

static int
luazmq_send(lua_State *L)
{
	void **sock;
	size_t len;
	int nbytes, flags;
	const char *buf;

	flags = lua_gettop(L) == 3 ? lua_tointeger(L, 3) : 0;
	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);
	buf = lua_tolstring(L, 2, &len);
	nbytes = zmq_send(*sock, buf, len, flags);
	lua_pushinteger(L, nbytes);
	return 1;
}

static int
luazmq_setsockopt(lua_State *L)
{
	void **sock;
	size_t len;
	int option_name;
	const char *option_value;

	sock = luaL_checkudata(L, 1, ZMQ_SOCKET_METATABLE);
	option_name = luaL_checkinteger(L, 2);
	option_value = luaL_checklstring(L, 3, &len);
	if (zmq_setsockopt(*sock, option_name, option_value, len))
		lua_pushnil(L);
	else
		lua_pushboolean(L, 1);
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

static void
luazmq_set_info(lua_State *L)
{
	lua_pushliteral(L, "_COPYRIGHT");
	lua_pushliteral(L, "Copyright (C) 2014 - 2019 by "
	    "micro systems marc balmer");
	lua_settable(L, -3);
	lua_pushliteral(L, "_DESCRIPTION");
	lua_pushliteral(L, "0MQ for Lua");
	lua_settable(L, -3);
	lua_pushliteral(L, "_VERSION");
	lua_pushliteral(L, "zmq 1.0.5");
	lua_settable(L, -3);
}

int
luaopen_zmq(lua_State *L)
{
	struct luaL_Reg functions[] = {
		{ "ctx_new",		luazmq_ctx_new },
		{ "curve_keypair",	luazmq_curve_keypair },
		{ "socket",		luazmq_socket },
		{ "strerror",		luazmq_strerror },
		{ "version",		luazmq_version },
		{ "z85_decode",		luazmq_z85_decode },
		{ "z85_encode",		luazmq_z85_encode },
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
		{ "msg_recv",		luazmq_msg_recv },
		{ "msg_send",		luazmq_msg_send },
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

        for (n = 0; n < num_zmq_int(); n++) {
                lua_pushinteger(L, zmq_int[n].value);
                lua_setfield(L, -2, zmq_int[n].name);
        };
        luazmq_set_info(L);
	return 1;
}
