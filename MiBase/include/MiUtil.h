#ifndef MiUtil_H_
#define MiUtil_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


typedef enum {
	Skt_Pro_Udp,
	Skt_Pro_Tcp
}ScktProType;

typedef enum {
	IpFaT_IPV4,
	IpFaT_IPV6
} IpFamilyType;

#ifndef NULL
#define NULL   0
#endif // !NULL

#define mi_memmove   memmove
#define mi_memcmp    memcmp
#define mi_memcpy    memcpy
#define mi_memset    memset
#define mi_calloc    calloc
#define mi_malloc    malloc
#define mi_free      free


#define mi_strlen               strlen
#define mi_strcpy               strcpy
#define mi_strstr               strstr
#define mi_sprintf              sprintf
#define mi_printf  printf
#define mi_sprintf sprintf
#define mi_snprintf snprintf
#define mi_vsnprintf vsnprintf
#define mi_sscanf   sscanf
#define mi_strcmp         strcmp


#define mi_tolower            tolower
#define mi_toupper            toupper

#define mi_atoi               atoi
#define mi_atol               atol



#define mi_bool               int32_t
#define mi_true                1
#define mi_false               0
#define mi_ok                  0

#define mi_min(a, b)          (((a) < (b))? (a) : (b))
#define mi_max(a, b)          (((a) < (b))? (b) : (a))

#define MI_UTIME_MILLISECONDS   1000
#define MI_UTIME_SECONDS 		1000000

#ifdef WIN32

	#define mi_sleep(x) Sleep(x)
	
#else
	#include <unistd.h>
	#define mi_sleep(x) usleep(x*1000)
#endif

uint64_t  __GetTickCount64();

#endif