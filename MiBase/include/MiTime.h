
#ifndef INCLUDE__MI_CTIME_H_
#define INCLUDE__MI_CTIME_H_
#include "MiUtil.h"
#define mi_time_t time_t

int64_t mi_get_system_micro_time();
int64_t mi_get_system_micro_time();

int64_t mi_get_milli_time();//haomiao
int64_t mi_get_micro_time();//weimiao

#define mi_get_milli_tick  mi_get_milli_time
#define mi_get_micro_tick  mi_get_micro_time


#if WIN32
#include <winsock2.h>
int gettimeofday(struct timeval *tp, void *tzp);
#endif
int64_t mi_get_nano_tick();//namiao
typedef struct MiNtp{
    uint64_t system_ms;
    uint64_t ntp;
    uint32_t ntp_second;
    uint32_t ntp_fractions;
}MiNtp;

uint64_t mi_get_ntptime_fromms(uint64_t ms);
uint64_t mi_get_ntptime_fromntp(uint64_t ntp);
void mi_ntp_from_time_ms(MiNtp* ntp,uint64_t ms);
void mi_ntp_to_time_ms(MiNtp* pntp,uint64_t ntp);


#define mi_get_system_time         mi_get_system_micro_time
void                               mi_update_system_time();

#endif
