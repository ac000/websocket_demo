/*
 * websocket.h - WebSocket frame header protocol
 *
 * WebSockets are defined here: http://tools.ietf.org/html/rfc6455
 *
 * Copyright (C) 2014, 2019	Andrew Clayton <andrew@digital-domain.net>
 *
 * Licensed under the GNU General Public License Version 2
 * See COPYING
 */

#ifndef _WEBSOCKET_H_
#define _WEBSOCKET_H_

#include <stdint.h>

#include "short_types.h"

#define SHORT_HDR_LEN		2
#define MAX_HDR_LEN		14
#define MKEY_LEN		4
#define PAYLEN_LEN		125
#define PAYLEN_LEN16		126
#define PAYLEN_LEN64		127

#define WS_KEY			"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/*
 * Structure idea from
 * http://www.altdevblogaday.com/2012/01/23/writing-your-own-websocket-server/
 *
 * It takes advantage of the fact that the websocket frame header will always
 * be at least 16bits. These 16bits are mapped into the two bytes within the
 * structure.
 *
 * The base frame protocol is described here:
 * http://tools.ietf.org/html/rfc6455#section-5.2
 */

struct websocket_header {
        u16 opcode:4;
        u16 rsv3:1;
        u16 rsv2:1;
        u16 rsv1:1;
        u16 fin:1;
        u16 pay_len:7;
        u16 masked:1;
};

static const char *websocket_opcodes[] = {
	"Continuation Frame",
	"Text Frame",
	"Binary Frame",
	"RESERVED",
	"RESERVED",
	"RESERVED",
	"RESERVED",
	"RESERVED",
	"Connection Close",
	"Ping",
	"Pong",
	"RESERVED",
	"RESERVED",
	"RESERVED",
	"RESERVED",
	"RESERVED" };

#endif /* _WEBSOCKET_H_ */
