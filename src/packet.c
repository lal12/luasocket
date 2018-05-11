/*=========================================================================*\
* Packet object
* LuaSocket toolkit
\*=========================================================================*/
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>

#include "lua.h"
#include "lauxlib.h"
#include "compat.h"

#include "auxiliar.h"
#include "socket.h"
#include "inet.h"
#include "options.h"
#include "packet.h"

/*=========================================================================*\
* Internal function prototypes
\*=========================================================================*/
static int global_create_link(lua_State *L);
static int global_create_net(lua_State *L);
static int global_if_indextoname(lua_State *L);
static int global_if_nametoindex(lua_State *L);
static int meth_send(lua_State *L);
static int meth_sendto(lua_State *L);
static int meth_getprotocol(lua_State *L);
static int meth_gettype(lua_State *L);
static int meth_getfamily(lua_State *L);
static int meth_gettimeout(lua_State *L);
static int meth_close(lua_State *L);
static int meth_settimeout(lua_State *L);
static int meth_getfd(lua_State *L);
static int meth_setfd(lua_State *L);
static int meth_dirty(lua_State *L);

/* udp object methods */
static luaL_Reg packet_methods[] = {
    {"__gc",        meth_close},
    {"__tostring",  auxiliar_tostring},
    {"close",       meth_close},
    {"dirty",       meth_dirty},
    {"send",        meth_send},
    {"sendto",      meth_sendto},
    {"gettype",     meth_gettype},
    {"getprotocol", meth_getprotocol},
    {"getfd",       meth_getfd},
    {"settimeout",  meth_settimeout},
    {"gettimeout",  meth_gettimeout},
    {NULL,          NULL}
};

/* functions in library namespace */
static luaL_Reg func[] = {
    {"packet_link", global_create_link},
    {"packet_net", global_create_net},
    {"ifindextoname", global_if_indextoname},
    {"ifnametoindex", global_if_nametoindex},
    {NULL, NULL}
};

/*-------------------------------------------------------------------------*\
* Initializes module
\*-------------------------------------------------------------------------*/
int packet_open(lua_State *L) {
    /* create classes */
    auxiliar_newclass(L, "packet{net}", packet_methods);
    auxiliar_newclass(L, "packet{link}", packet_methods);
    /* create class groups */
    auxiliar_add2group(L, "packet{net}", "packet{any}");
    auxiliar_add2group(L, "packet{link}", "packet{any}");
    auxiliar_add2group(L, "packet{net}", "select{able}");
    auxiliar_add2group(L, "packet{link}", "select{able}");
    /* define library functions */
    luaL_setfuncs(L, func, 0);
    return 0;
}

/*=========================================================================*\
* Lua methods
\*=========================================================================*/
static const char *packet_strerror(int err) {
    /* a 'closed' error on an unconnected means the target address was not
     * accepted by the transport layer */
    if (err == IO_CLOSED) return "refused";
    else return socket_strerror(err);
}

/*-------------------------------------------------------------------------*\
* Send data through link packet socket
\*-------------------------------------------------------------------------*/
static int meth_send(lua_State *L) {
    p_packet pkt = (p_packet) auxiliar_checkclass(L, "packet{link}", 1);
    p_timeout tm = &pkt->tm;
    size_t count, sent = 0;
    int err;
    const char *data = luaL_checklstring(L, 2, &count);
    if(pkt->ifindex < 0){
        lua_pushnil(L);
        lua_pushliteral(L, "Not bound!");
        return 2;
    }

    timeout_markstart(tm);
    err = socket_send(&pkt->sock, data, count, &sent, tm);
    if (err != IO_DONE) {
        lua_pushnil(L);
        lua_pushstring(L, packet_strerror(err));
        return 2;
    }
    lua_pushnumber(L, (lua_Number) sent);
    return 1;
}


static int parseMac(const char* str, uint8_t* mac){
    int values[6];
    if( 6 == sscanf( str, "%x:%x:%x:%x:%x:%x%*c",
        &values[0], &values[1], &values[2],
        &values[3], &values[4], &values[5] ) )
    {
        for( int i = 0; i < 6; ++i )
            mac[i] = (uint8_t) values[i];
        return 0;
    }else{
        return -1;
    }
}

/*-------------------------------------------------------------------------*\
* Send data through net packet socket
\*-------------------------------------------------------------------------*/
static int meth_sendto(lua_State *L) {
    p_packet pkt = (p_packet) auxiliar_checkclass(L, "packet{net}", 1);
    size_t count, sent = 0;
    const char *data = luaL_checklstring(L, 2, &count);
    const char *mac = luaL_checkstring(L, 3);
    int ifindex = pkt->ifindex; // If already bound to interface use the ifindex
    if(ifindex < 0) 
        ifindex = luaL_checkinteger(L, 4);
    p_timeout tm = &pkt->tm;
    int err;
    struct addrinfo ai;
    struct sockaddr_ll addr = {0};
    uint8_t macaddr[6];

    if(parseMac(mac, macaddr)){
        lua_pushnil(L);
        lua_pushliteral(L, "invalid mac format!");
        return 2;
    }

    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    addr.sll_protocol = htons(pkt->protocol);
    memcpy(addr.sll_addr, macaddr, 6);

    memset(&ai, 0, sizeof(ai));
    ai.ai_family = AF_PACKET;
    ai.ai_socktype = SOCK_DGRAM;
    ai.ai_flags = 0;
    ai.ai_addr = (struct sockaddr*) &addr;
    ai.ai_addrlen = sizeof(addr);

    timeout_markstart(tm);
    err = socket_sendto(&pkt->sock, data, count, &sent, ai.ai_addr, (socklen_t) ai.ai_addrlen, tm);
    if (err != IO_DONE) {
        lua_pushnil(L);
        lua_pushstring(L, packet_strerror(err));
        return 2;
    }
    lua_pushnumber(L, (lua_Number) sent);
    return 1;
}

/*-------------------------------------------------------------------------*\
* Returns type as string
\*-------------------------------------------------------------------------*/
static int meth_gettype(lua_State *L) {
    p_packet pkt = (p_packet) auxiliar_checkgroup(L, "packet{any}", 1);
    if (pkt->type == SOCK_DGRAM) {
        lua_pushliteral(L, "net");
        return 1;
    } else { // pkt->type == SOCK_RAW
        lua_pushliteral(L, "link");
        return 1;
    }
}

/*-------------------------------------------------------------------------*\
* Returns protocol as number
\*-------------------------------------------------------------------------*/
static int meth_getprotocol(lua_State *L) {
    p_packet pkt = (p_packet) auxiliar_checkgroup(L, "packet{any}", 1);
    lua_pushnumber(L, pkt->protocol);
    return 1;
}

/*-------------------------------------------------------------------------*\
* Select support methods
\*-------------------------------------------------------------------------*/
static int meth_getfd(lua_State *L) {
    p_packet pkt = (p_packet) auxiliar_checkgroup(L, "packet{any}", 1);
    lua_pushnumber(L, (int) pkt->sock);
    return 1;
}

/* this is very dangerous, but can be handy for those that are brave enough */
static int meth_setfd(lua_State *L) {
    p_packet pkt = (p_packet) auxiliar_checkgroup(L, "packet{any}", 1);
    pkt->sock = (t_socket) luaL_checknumber(L, 2);
    return 0;
}

static int meth_dirty(lua_State *L) {
    p_packet pkt = (p_packet) auxiliar_checkgroup(L, "packet{any}", 1);
    (void) pkt;
    lua_pushboolean(L, 0);
    return 1;
}

/*-------------------------------------------------------------------------*\
* Just call tm methods
\*-------------------------------------------------------------------------*/
static int meth_settimeout(lua_State *L) {
    p_packet pkt = (p_packet) auxiliar_checkgroup(L, "packet{any}", 1);
    return timeout_meth_settimeout(L, &pkt->tm);
}

static int meth_gettimeout(lua_State *L) {
    p_packet pkt = (p_packet) auxiliar_checkgroup(L, "packet{any}", 1);
    return timeout_meth_gettimeout(L, &pkt->tm);
}

/*-------------------------------------------------------------------------*\
* Closes socket used by object
\*-------------------------------------------------------------------------*/
static int meth_close(lua_State *L) {
    p_packet pkt = (p_packet) auxiliar_checkgroup(L, "packet{any}", 1);
    socket_destroy(&pkt->sock);
    lua_pushnumber(L, 1);
    return 1;
}

/*=========================================================================*\
* Library functions
\*=========================================================================*/
/*-------------------------------------------------------------------------*\
* Creates a master packet object
\*-------------------------------------------------------------------------*/
static int packet_create(lua_State *L, int type) {
    int protocol = luaL_checknumber(L, 1);
    p_packet pkt = (p_packet) lua_newuserdata(L, sizeof(t_packet));
    if(type == SOCK_RAW){
        auxiliar_setclass(L, "packet{link}", -1);
    }else{ // type == SOCK_DGRAM
        auxiliar_setclass(L, "packet{net}", -1);
    }
    timeout_init(&pkt->tm, -1, -1);
    pkt->type = type;
    pkt->protocol = protocol;
    // ifindex is set automatically in bind, then it does not need to passed as parameter on send functions
    pkt->ifindex = -1;
    int err = socket_create(&pkt->sock, AF_PACKET, type, htons(protocol));
    if (err != 0) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(err));
        return 2;
    }
    socket_setnonblocking(&pkt->sock);
    return 1;
}

static int global_create_net(lua_State *L) {
    return packet_create(L, SOCK_DGRAM);
}

static int global_create_link(lua_State *L) {
    return packet_create(L, SOCK_RAW);
}

static int global_if_indextoname(lua_State *L){
    int ifindex = luaL_checkinteger(L, 1);
    char* ifname = if_indextoname(ifindex, NULL);
    if(ifname == NULL){
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }
    lua_pushstring(L, ifname);
    return 1;
}

static int global_if_nametoindex(lua_State *L){
    const char* ifname = luaL_checkstring(L, 1);
    int ifindex = if_nametoindex(ifname);
    if(ifindex == 0){
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }
    lua_pushinteger(L, ifindex);
    return 1;
}
