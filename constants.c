/*
 * Copyright (c) 2014, 2015 Micro Systems Marc Balmer, CH-5073 Gipf-Oberfrick.
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

/* 0MQ constants */

#include <zmq.h>

#include "luazmq.h"

#define ZMQ(NAME)		{ #NAME, ZMQ_##NAME }

struct int_constant zmq_int[] = {
	/* Socket types */
	ZMQ(PAIR),
	ZMQ(PUB),
	ZMQ(SUB),
	ZMQ(REQ),
	ZMQ(REP),
	ZMQ(DEALER),
	ZMQ(ROUTER),
	ZMQ(PULL),
	ZMQ(PUSH),
	ZMQ(XPUB),
	ZMQ(XSUB),
	ZMQ(STREAM),

	/* Socket options */
	ZMQ(AFFINITY),
	ZMQ(IDENTITY),
	ZMQ(SUBSCRIBE),
	ZMQ(UNSUBSCRIBE),
	ZMQ(RATE),
	ZMQ(RECOVERY_IVL),
	ZMQ(SNDBUF),
	ZMQ(RCVBUF),
	ZMQ(RCVMORE),
	ZMQ(FD),
	ZMQ(EVENTS),
	ZMQ(TYPE),
	ZMQ(LINGER),
	ZMQ(RECONNECT_IVL),
	ZMQ(BACKLOG),
	ZMQ(RECONNECT_IVL_MAX),
	ZMQ(MAXMSGSIZE),
	ZMQ(SNDHWM),
	ZMQ(RCVHWM),
	ZMQ(MULTICAST_HOPS),
	ZMQ(RCVTIMEO),
	ZMQ(SNDTIMEO),
	ZMQ(LAST_ENDPOINT),
	ZMQ(ROUTER_MANDATORY),
	ZMQ(TCP_KEEPALIVE),
	ZMQ(TCP_KEEPALIVE_CNT),
	ZMQ(TCP_KEEPALIVE_IDLE),
	ZMQ(TCP_KEEPALIVE_INTVL),
	ZMQ(TCP_ACCEPT_FILTER),
	ZMQ(IMMEDIATE),
	ZMQ(XPUB_VERBOSE),
	ZMQ(ROUTER_RAW),
	ZMQ(IPV6),
	ZMQ(MECHANISM),
	ZMQ(PLAIN_SERVER),
	ZMQ(PLAIN_USERNAME),
	ZMQ(PLAIN_PASSWORD),
	ZMQ(CURVE_SERVER),
	ZMQ(CURVE_PUBLICKEY),
	ZMQ(CURVE_SECRETKEY),
	ZMQ(CURVE_SERVERKEY),
	ZMQ(PROBE_ROUTER),
	ZMQ(REQ_CORRELATE),
	ZMQ(REQ_RELAXED),
	ZMQ(CONFLATE),
	ZMQ(ZAP_DOMAIN),

	/* Message options */
	ZMQ(MORE),

	/* Send/recv options */
	ZMQ(DONTWAIT),
	ZMQ(SNDMORE),

	/* Security mechanisms */
	ZMQ(NULL),
	ZMQ(PLAIN),
	ZMQ(CURVE),

	/* Socket transport events (tcp and ipc only) */
	ZMQ(EVENT_CONNECTED),
	ZMQ(EVENT_CONNECT_DELAYED),
	ZMQ(EVENT_CONNECT_RETRIED),

	ZMQ(EVENT_LISTENING),
	ZMQ(EVENT_BIND_FAILED),

	ZMQ(EVENT_ACCEPTED),
	ZMQ(EVENT_ACCEPT_FAILED),

	ZMQ(EVENT_CLOSED),
	ZMQ(EVENT_CLOSE_FAILED),
	ZMQ(EVENT_DISCONNECTED),
	ZMQ(EVENT_MONITOR_STOPPED),

	ZMQ(EVENT_ALL),

	/* I/O multiplexing */
	ZMQ(POLLIN),
	ZMQ(POLLOUT),
	ZMQ(POLLERR),
	ZMQ(POLLITEMS_DFLT)
};

size_t
num_zmq_int(void)
{
	return sizeof(zmq_int)/sizeof(zmq_int[0]);
}
