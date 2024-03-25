
#ifndef UTIL_TIMER_H_
#define UTIL_TIMER_H_
#include "MiUtil.h"
#include <stdint.h>
#include "MiThread.h"

#if MI_OS_APPLE
	#include <dispatch/dispatch.h>
#endif
typedef struct MiTimer{
	int32_t taskId;

	int32_t isStart;
	int32_t isloop;
	int32_t waitState;
	int32_t waitTime;
	mi_thread_t threadId;
#if Mi_Enable_Timer_Phtread
	mi_thread_mutex_t t_lock;
	mi_thread_cond_t t_cond_mess;
#else
    #if WIN32
        HANDLE	hTimerQueue;
        HANDLE	hTimerQueueTimer;
        HANDLE  winEvent;
	#elif MI_OS_APPLE
		dispatch_source_t _timer;
	#else
        int32_t timerfd;
        int32_t efd;
    #endif
#endif
	void (*doTask)(int32_t taskId,void* user);
	void* user;
}MiTimer;
#ifdef __cplusplus
extern "C"{
#endif
void mi_create_timer(MiTimer* timer,void* user,int32_t taskId,int32_t waitTime);
void mi_destroy_timer(MiTimer* timer);
void mi_timer_start(MiTimer* timer);
void mi_timer_stop(MiTimer* timer);
#ifdef __cplusplus
}
#endif


#endif 
