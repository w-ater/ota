#ifndef MI_SOCKETUTIL_H_
#define MI_SOCKETUTIL_H_


#if WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <errno.h>
#define socklen_t int
#define mi_be32toh ntohl
#define GetSockError()	WSAGetLastError()
#define SetSockError(e)	WSASetLastError(e)
#define setsockopt(a,b,c,d,e)	(setsockopt)(a,b,c,(const char *)d,(int)e)
#define MI_NO_SIGNAL 0
#define mi_poll WSAPoll
#else
#include <netinet/in.h>
#include <errno.h>
	#if MI_OS_APPLE
		#include <TargetConditionals.h>
        #include <libkern/OSByteOrder.h>
        #define mi_be32toh OSSwapBigToHostInt32
		#define MI_NO_SIGNAL SO_NOSIGPIPE
	#else
        #define mi_be32toh be32toh
		#define MI_NO_SIGNAL MSG_NOSIGNAL
	#endif

#define mi_poll poll
#define GetSockError()	errno
#define SetSockError(e)	errno = e
#endif


#include <stdint.h>
#include "MiVector.h"

#define mi_ntohl ntohl
#define mi_htons htons
#define mi_ntohs ntohs
#define mi_inet_addr inet_addr
#define mi_inet_pton inet_pton
#define mi_inet_ntoa inet_ntoa


#define mi_socket_t int
typedef struct sockaddr_in    mi_socket_addr4;
typedef struct sockaddr_in6   mi_socket_addr6;


typedef struct {
    int32_t port;
    uint32_t mapAddress;
    IpFamilyType familyType;
    ScktProType protocol;

    uint8_t  address[16];
    mi_socket_addr4 addr4;
    mi_socket_addr6 addr6;

} MiIpAddress;

#ifdef __cplusplus
extern "C"{
#endif

void mi_addr_set(MiIpAddress* addr,char* ip,int32_t port, IpFamilyType familyType, ScktProType protocol);
void mi_addr_setAnyAddr(MiIpAddress* addr,int32_t port, IpFamilyType familyType, ScktProType protocol);

void mi_addr_setIPV4(MiIpAddress* addr,int32_t ip,int32_t port, ScktProType protocol);
void mi_addr_setIPV6(MiIpAddress* addr,uint8_t ip[16],int32_t port, ScktProType protocol);
uint32_t mi_addr_getIP(MiIpAddress* addr);
void mi_addr_getIPStr(MiIpAddress* addr,char* addrstr,int32_t strLen);
uint16_t mi_addr_getPort(MiIpAddress* addr);
uint16_t mi_addr_getSinPort(MiIpAddress* addr);
mi_socket_t mi_socket_create(IpFamilyType familyType, ScktProType protocol);
//non-block socket
int32_t mi_socket_setNonblock(mi_socket_t fd);
int32_t mi_socket_close(mi_socket_t fd);

int32_t mi_socket_listen(mi_socket_t fd, MiIpAddress* addr);

int32_t mi_socket_connect(mi_socket_t fd, MiIpAddress* remoteAddr);
int32_t mi_socket_recvfrom(mi_socket_t fd,char* buffer,int32_t bufferLen, MiIpAddress* addr);

int32_t mi_socket_accept(mi_socket_t fd, MiIpAddress* addr);

int32_t mi_socket_sendto(mi_socket_t fd,char* data,int32_t nb, MiIpAddress* remote_addr,int32_t flag);
int32_t mi_socket_send(mi_socket_t fd,char* data,int32_t nb);
int32_t mi_socket_send2(mi_socket_t fd,char* data,int32_t nb,int32_t flag);
int32_t mi_socket_recv(mi_socket_t fd,char* data,int32_t nb,int32_t flag);


int32_t mi_getLocalInfo(IpFamilyType familyType,char* p);
int32_t mi_getLocalInfoList(IpFamilyType familyType,MiStringVector* p);
int32_t mi_getIp(IpFamilyType familyType, char* domain, char* ip);

#ifdef __cplusplus
}
#endif
#endif
