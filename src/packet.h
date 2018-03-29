#ifndef PACKET_H
#define PACKET_H
/*=========================================================================*\
* packet object
* LuaSocket toolkit
*
* The packet.h module provides LuaSocket with support packet sockets
* (AF_PACKET, SOCK_DGRAM).
* (AF_PACKET, SOCK_RAW).
*
* Two classes are defined: connected and unconnected. UDP objects are
* originally unconnected. They can be "connected" to a given address
* with a call to the setpeername function. The same function can be used to
* break the connection.
\*=========================================================================*/
#include "lua.h"

#include "timeout.h"
#include "socket.h"


typedef struct t_packet_ {
    t_socket sock;
    t_timeout tm;
    int type;
    int protocol;
    int ifindex;
} t_packet;
typedef t_packet *p_packet;

int packet_open(lua_State *L);

#endif /* PACKET_H */
