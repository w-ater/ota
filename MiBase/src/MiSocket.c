
#include "MiSocket.h"
#include "MiLog.h"

#if WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#define mi_poll WSAPoll
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#endif

#include <fcntl.h>

#define mi_sockaddr(x)      x->familyType == IpFaT_IPV4 ? (const struct sockaddr*)(&x->addr4):(const struct sockaddr*)(&x->addr6)
#define mi_sockaddr2(x)     x->familyType == IpFaT_IPV4 ? (struct sockaddr*)(&x->addr4):(struct sockaddr*)(&x->addr6)
#define mi_sockaddr_len(x)  x->familyType == IpFaT_IPV4 ? sizeof(mi_socket_addr4):sizeof(mi_socket_addr6);

void mi_addr_set(MiIpAddress* addr,char* ip,int32_t port, IpFamilyType familyType, ScktProType protocol){
	if(addr==NULL) return;
	addr->port=port;
	addr->familyType=familyType;
	addr->protocol=protocol;
	mi_memcpy(addr->address,ip, mi_strlen(ip));
	if(familyType== IpFaT_IPV4){
		addr->addr4.sin_family = AF_INET;
		addr->addr4.sin_port = mi_htons(addr->port);
#if WIN32
		addr->addr4.sin_addr.S_un.S_addr= mi_inet_addr(ip);
#else
		addr->addr4.sin_addr.s_addr = mi_inet_addr(ip);
#endif
	}else{
		addr->addr6.sin6_family = AF_INET6;
		addr->addr6.sin6_port = mi_htons(addr->port);
		mi_inet_pton(AF_INET6, ip, &addr->addr6.sin6_addr);
	}
}

void mi_addr_setAnyAddr(MiIpAddress* addr,int32_t port, IpFamilyType familyType, ScktProType protocol){
	if(familyType== IpFaT_IPV6)
	{
		uint8_t ip[16]={0};
		mi_addr_setIPV6(addr,ip,port,protocol);
		return;
	}
    mi_addr_setIPV4(addr,0,port,protocol);
}

void mi_addr_setIPV4(MiIpAddress* addr,int32_t ip,int32_t port, ScktProType protocol){
	if(addr==NULL) 
		return;
	addr->port=port;
	addr->familyType= IpFaT_IPV4;
	addr->protocol=protocol;


		addr->addr4.sin_family = AF_INET;
		addr->addr4.sin_port = mi_htons(addr->port);
#if WIN32
		addr->addr4.sin_addr.S_un.S_addr=ip;
#else
		addr->addr4.sin_addr.s_addr = ip;
#endif

}


void mi_addr_setIPV6(MiIpAddress* addr,uint8_t ip[16],int32_t port, ScktProType protocol){
	if(addr==NULL) 
		return;
	addr->port=port;
	addr->familyType= IpFaT_IPV6;
	addr->protocol=protocol;
	addr->addr6.sin6_family = AF_INET6;
	addr->addr6.sin6_port = mi_htons(addr->port);
	mi_memcpy(&addr->addr6.sin6_addr,ip,16);

}

void mi_addr_getIPStr(MiIpAddress* addr,char* addrstr,int32_t strLen){
	if(addr->familyType == IpFaT_IPV4)
		inet_ntop(AF_INET,&addr->addr4.sin_addr.s_addr, addrstr, strLen);
	else
        inet_ntop(AF_INET6,&addr->addr6.sin6_addr, addrstr, strLen);
}

uint32_t mi_addr_getIP(MiIpAddress* addr){
#if WIN32
	return addr->addr4.sin_addr.S_un.S_addr;
#else
	return addr->addr4.sin_addr.s_addr;
#endif

}

uint16_t mi_addr_getPort(MiIpAddress* addr){
	return mi_htons(addr->familyType == IpFaT_IPV4 ?addr->addr4.sin_port:addr->addr6.sin6_port);
}

uint16_t mi_addr_getSinPort(MiIpAddress* addr){
	return addr->familyType == IpFaT_IPV4 ?addr->addr4.sin_port:addr->addr6.sin6_port;
}

mi_socket_t mi_socket_create(IpFamilyType familyType, ScktProType protocol){
#if WIN32
    WORD wVersionRequested;
    WSADATA wsaData;
    wVersionRequested = MAKEWORD(2, 2);
    WSAStartup(wVersionRequested, &wsaData);
#endif

    int32_t fd=-1;
	fd = socket(familyType == IpFaT_IPV4 ? AF_INET : AF_INET6, protocol== Skt_Pro_Tcp ?SOCK_STREAM:SOCK_DGRAM, 0);

	if(fd==-1){
		mi_error("create socket error: %d ", GetSockError());
		return fd;
	}

	int32_t timeoutMs=800;
#if WIN32
    int32_t timeout=timeoutMs;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &timeout,  sizeof(timeout));
#else
	struct timeval tv;
	tv.tv_sec = 0;
    tv.tv_usec = timeoutMs*1000;  //  ms
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*) &tv,	sizeof(struct timeval));
	int value = 1;
	setsockopt(fd, SOL_SOCKET, MI_NO_SIGNAL, &value, sizeof(value));
#endif

	if(protocol== Skt_Pro_Tcp){
		//int sendBufSize=32*1024;
		//setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sendBufSize, sizeof(sendBufSize));

		int32_t on = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*) &on, sizeof(on));
	}

	return fd;

}
int32_t mi_socket_setNonblock(mi_socket_t fd) {
#if WIN32
	if (fd != INVALID_SOCKET) {
		int iMode = 1;
		ioctlsocket(fd, FIONBIO,  & iMode);
	}
#else
	if (fd != -1) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
#endif
	return mi_ok;
}



int32_t mi_socket_close(mi_socket_t fd){
#if WIN32
	closesocket(fd);
#else
	close(fd);
#endif

	return mi_ok;
}

int32_t mi_socket_listen(mi_socket_t fd,MiIpAddress* addr){
	int32_t err= mi_ok;
	socklen_t addrLen= mi_sockaddr_len(addr);
	if((err=bind(fd, mi_sockaddr(addr),addrLen))!=mi_ok){
		return mi_error_wrap(err,"socket bind error");
	}
	if(addr->protocol== Skt_Pro_Tcp){
		return listen(fd,5);
	}
	return mi_ok;

}



int32_t mi_socket_connect(mi_socket_t fd, MiIpAddress* remoteAddr){
	socklen_t addrLen= mi_sockaddr_len(remoteAddr);
	return connect(fd, mi_sockaddr(remoteAddr),addrLen);
}

int32_t mi_socket_recvfrom(mi_socket_t fd,char* buffer,int32_t bufferLen, MiIpAddress* addr){
	socklen_t srcLen= mi_sockaddr_len(addr);
	return recvfrom(fd, buffer, bufferLen, 0, mi_sockaddr2(addr), &srcLen);
}

int32_t mi_socket_sendto(mi_socket_t fd,char* data,int32_t nb, MiIpAddress* remote_addr,int32_t flag){
	socklen_t addrLen= mi_sockaddr_len(remote_addr);
	return sendto(fd, data, nb, flag, mi_sockaddr(remote_addr),addrLen);
}

int32_t mi_socket_send(mi_socket_t fd,char* data,int32_t nb){
	return send(fd, data, nb, MI_NO_SIGNAL);
}

int32_t mi_socket_send2(mi_socket_t fd,char* data,int32_t nb,int32_t flag){
	return send(fd, data, nb, flag);
}

int32_t mi_socket_recv(mi_socket_t fd,char* data,int32_t nb,int32_t flag){
	return recv(fd, data, nb, flag);
}

int32_t mi_socket_accept(mi_socket_t fd,MiIpAddress* addr){
	socklen_t addrLen=mi_sockaddr_len(addr);
	return accept(fd, mi_sockaddr2(addr), &addrLen);
}

