#include "MiTime.h"
#include <time.h>

#ifdef _MSC_VER
#define FILETIME_1970 116444736000000000ull /* seconds between 1/1/1601 and 1/1/1970 */
#define HECTONANOSEC_PER_SEC 10000000ull
union mi_gettimeofday_type {
	unsigned long long ns100; //time since 1 Jan 1601 in 100ns units
	FILETIME ft;
}  ;
int gettimeofday(struct timeval *tp, void *tzp)
{
	union mi_gettimeofday_type t_now;
	GetSystemTimeAsFileTime(&t_now.ft);
	//100 nano-seconds since 1-1-1970
	t_now.ns100 -= FILETIME_1970;
	tp->tv_sec=t_now.ns100 / HECTONANOSEC_PER_SEC;
	tp->tv_usec=(t_now.ns100 % HECTONANOSEC_PER_SEC)/10;

	return (0);
}
int64_t mi_get_win_micro_time();
#define mi_micro_time mi_get_win_micro_time
#else
#include <sys/time.h>
#define mi_micro_time  mi_get_micro_time
#endif

int64_t g_system_time_startup_time = 0;
#ifdef _MSC_VER
LARGE_INTEGER  g_large_interger;
int64_t g_dff=0;
#endif
#define MI_TIME_RESOLUTION_US 300*1000
void mi_update_system_time() 
{ //milli weimiao
#ifdef _MSC_VER
	if(g_dff==0){
		QueryPerformanceFrequency(&g_large_interger);
		g_dff = g_large_interger.QuadPart;
	}
	if(g_system_time_startup_time==0){
		QueryPerformanceCounter(&g_large_interger);
		g_system_time_startup_time=g_large_interger.QuadPart;
	}
#else
	if(g_system_time_startup_time==0) 
		g_system_time_startup_time = mi_get_micro_time();

#endif

}

int64_t mi_get_system_micro_time()
{
	if(g_system_time_startup_time==0) 
		mi_update_system_time();
	return mi_micro_time()-g_system_time_startup_time;
}

int64_t mi_get_system_milli_time(){
	if(g_system_time_startup_time==0) 
		mi_update_system_time();

	return mi_micro_time()/1000;

}



#ifdef _MSC_VER

int64_t mi_get_win_micro_time()
{
	// if(g_system_time_startup_time==0) mi_update_system_time();
	QueryPerformanceCounter(&g_large_interger);
	return (g_large_interger.QuadPart-g_system_time_startup_time)*1000000/g_dff;
}
int64_t mi_get_win_milli_time()
{
	if(g_system_time_startup_time==0) 
		mi_update_system_time();
	QueryPerformanceCounter(&g_large_interger);
	return (g_large_interger.QuadPart-g_system_time_startup_time)*1000/g_dff;

}
#else
//namiao
int64_t mi_get_nano_tick()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec * 1000000000 + ts.tv_nsec);
}

#endif


//weimiao
int64_t mi_get_micro_time() {
	struct timeval time;
	gettimeofday(&time, 0);
	return time.tv_sec * 1000000 + time.tv_usec ;
}
//haomiao
int64_t mi_get_milli_time() {
	struct timeval time;
	gettimeofday(&time, 0);
	// long millis = (time.tv_sec * 1000) + (time.tv_usec / 1000);
	return (time.tv_sec * 1000) + (time.tv_usec / 1000);
}


const uint64_t kMagicNtpFractionalUnit = ((uint64_t)1) << 32;



void mi_ntp_from_time_ms(MiNtp* ntp,uint64_t ms)
{

	ntp->system_ms = ms;
	ntp->ntp_second = ms / 1000;
	ntp->ntp_fractions = ((double)(ms % 1000 / 1000.0)) * kMagicNtpFractionalUnit;
	ntp->ntp = ((uint64_t)(ntp->ntp_second) << 32) | ntp->ntp_fractions;
}

uint64_t mi_get_ntptime_fromntp(uint64_t pntp){
	return ((uint64_t)((pntp & 0xFFFFFFFF00000000ULL) >> 32) * 1000) +
				((double)((uint64_t)(pntp & 0x00000000FFFFFFFFULL) * 1000.0) / kMagicNtpFractionalUnit);
}

uint64_t mi_get_ntptime_fromms(uint64_t ms){
	uint32_t ntp_fractions = ((double)(ms % 1000 / 1000.0)) * kMagicNtpFractionalUnit;
	uint64_t ntp_second = (ms / 1000)<<32;
	return ntp_second  | ntp_fractions;
}


void mi_ntp_to_time_ms(MiNtp* ntp,uint64_t pntp)
{

	ntp->ntp =pntp;
	ntp->ntp_second = (pntp & 0xFFFFFFFF00000000ULL) >> 32;
	ntp->ntp_fractions = (pntp & 0x00000000FFFFFFFFULL);
	ntp->system_ms = ((uint64_t)(ntp->ntp_second) * 1000) +
			((double)((uint64_t)(ntp->ntp_fractions) * 1000.0) / kMagicNtpFractionalUnit);

}
