
#include "MiTimer.h"
#include "MiLog.h"
#if !Mi_Enable_Timer_Phtread
#if WIN32
void  CALLBACK g_mi_TimeEvent(PVOID user, BOOLEAN TimerOrWaitFired2)
{
    MiTimer* timer=(MiTimer*)user;
    if(timer->doTask) 
		timer->doTask(timer->taskId,timer->user);
    return;
}
void g_mi_startWindowsEventTime2(int pwaitTime, MiTimer *timer)
{
    if(timer==NULL) 
		return;

    timer->hTimerQueue = CreateTimerQueue();
    if(timer->hTimerQueue!=NULL){
        if (!CreateTimerQueueTimer(&timer->hTimerQueueTimer, timer->hTimerQueue, g_mi_TimeEvent, timer, 0, pwaitTime, WT_EXECUTEDEFAULT))
        {
            timer->hTimerQueue = NULL;
            timer->hTimerQueueTimer = NULL;
        }
    }


    return;
}
#else
#include <sys/time.h>
    #if !MI_OS_APPLE
		#include <sys/timerfd.h>
		#include <sys/epoll.h>
	#endif
#endif
#endif
#include <fcntl.h>

void mi_create_timer(MiTimer *timer, void *user, int32_t taskId,
		int32_t waitTime) {
	if (timer == NULL)
		return;
	timer->isloop = mi_false;
	timer->isStart = mi_false;
	timer->waitState = 0;
	timer->waitTime = waitTime;
#if Mi_Enable_Timer_Phtread
	mi_thread_mutex_init(&timer->t_lock,NULL);
	mi_thread_cond_init(&timer->t_cond_mess,NULL);
#else
#if WIN32
    timer->hTimerQueue=NULL;
    timer->hTimerQueueTimer=NULL;
    timer->winEvent=CreateEvent(NULL,TRUE,FALSE,NULL);
#elif mi_OS_APPLE
	timer->_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(0, 0));
#else
    timer->timerfd = timerfd_create(CLOCK_REALTIME, 0);//TFD_NONBLOCK | TFD_CLOEXEC);
    timer->efd = -1;
#endif

#endif

	timer->user = user;
	timer->doTask = NULL;
	timer->taskId = taskId;
}
void mi_destroy_timer(MiTimer *timer) {
	if (timer == NULL)		return;
#if Mi_Enable_Timer_Phtread
	mi_thread_mutex_destroy(&timer->t_lock);
	mi_thread_cond_destroy(&timer->t_cond_mess);
#endif
}
void* mi_run_timer_thread(void *obj) {
	MiTimer *timer = (MiTimer*) obj;
	timer->isStart = mi_true;
	timer->isloop = mi_true;
#if Mi_Enable_Timer_Phtread
    struct timespec outtime;
    struct timeval now;
    mi_thread_mutex_lock(&timer->t_lock);
    while (timer->isloop) {
        gettimeofday(&now, NULL);

        long nsec = now.tv_usec * 1000 + (timer->waitTime % 1000) * 1000000;
        outtime.tv_sec=now.tv_sec + nsec / 1000000000 + timer->waitTime / 1000;
        outtime.tv_nsec=nsec % 1000000000;

        timer->waitState=1;

        mi_thread_cond_timedwait(&timer->t_cond_mess, &timer->t_lock,&outtime);
        timer->waitState=0;
        if(timer->doTask) 
			timer->doTask(timer->taskId, timer->user);
    }
    mi_thread_mutex_unlock(&timer->t_lock);
#else
    #if WIN32
    g_mi_startWindowsEventTime2(timer->waitTime,timer);
    if(WaitForSingleObject(timer->winEvent,INFINITE) !=WAIT_OBJECT_0)
    {
        mi_error("miTimer WaitForSingleObject fail");
    }

    CloseHandle(timer->winEvent);
    timer->winEvent=NULL;
	#elif MI_OS_APPLE

    #else
	struct itimerspec itimer;
	itimer.it_value.tv_sec = timer->waitTime / 1000;
	itimer.it_value.tv_nsec = (timer->waitTime % 1000) * 1000 * 1000;
	itimer.it_interval.tv_sec = timer->waitTime / 1000;
	itimer.it_interval.tv_nsec = (timer->waitTime % 1000) * 1000 * 1000;
	int ret = timerfd_settime(timer->timerfd, TFD_TIMER_ABSTIME, &itimer, NULL);
	if (ret == -1) {
		mi_error("timerfd_settime");
	}

	int opts;
	opts = fcntl(timer->timerfd, F_GETFL);
	if (opts < 0) {
		mi_error("fcntl(sock,GETFL)");
		_exit(1);
	}
	opts = opts | O_NONBLOCK;
	if (fcntl(timer->timerfd, F_SETFL, opts) < 0) {
		mi_error("fcntl(sock,SETFL,opts)");
		_exit(1);
	}
	timer->efd = epoll_create1(0);
	struct epoll_event tev;
	tev.events = EPOLLIN | EPOLLET;
	tev.data.fd = timer->timerfd;
	epoll_ctl(timer->efd, EPOLL_CTL_ADD, timer->timerfd, &tev);
	struct epoll_event ev[1];
	while (timer->isloop) {
       // int nev = epoll_wait(timer->efd, ev, 1, 0);
        int nev = epoll_wait(timer->efd, ev, 1, mi_CTimer_Epoll_Timeout);
		if (nev > 0 && (ev[0].events & EPOLLIN)) {
			uint64_t res;
			int bytes =	read(timer->timerfd, &res, sizeof(res));
			(void)bytes;
			if (timer->doTask)
				timer->doTask(timer->taskId, timer->user);
		}
	}
    #endif

#endif
	timer->isStart = mi_false;
	return NULL;
}
void mi_timer_start(MiTimer *timer) {
	if (timer == NULL||timer->isStart)
		return;

#if MI_OS_APPLE
	dispatch_source_set_timer(timer->_timer, DISPATCH_TIME_NOW, timer->waitTime * NSEC_PER_MSEC, timer->waitTime * NSEC_PER_MSEC);
	dispatch_source_set_event_handler(timer->_timer, ^{
         if(timer->doTask) 
		 timer->doTask(timer->taskId,timer->user);
	});
    timer->isStart = mitrue;
    timer->isloop = mitrue;

	dispatch_resume(timer->_timer);
#else
    if (mi_thread_create(&timer->threadId, 0, mi_run_timer_thread, timer)) {
        mi_error("miThread::start could not start thread");

    }
#endif
}
void mi_timer_stop(MiTimer *timer) {
	if (timer == NULL||!timer->isStart)
		return;
	if (timer->isStart) {
		timer->isloop = mi_false;

#if Mi_Enable_Timer_Phtread
    if(timer->waitState){
		mi_thread_mutex_lock(&timer->t_lock);
		mi_thread_cond_signal(&timer->t_cond_mess);
		mi_thread_mutex_unlock(&timer->t_lock);

    }
	while (timer->isStart)
		mi_sleep(10);
#else

    #if WIN32
    if (timer->hTimerQueueTimer != NULL)
        DeleteTimerQueueTimer(timer->hTimerQueue, timer->hTimerQueueTimer, INVALID_HANDLE_VALUE);
    if (timer->hTimerQueue != NULL)
        DeleteTimerQueueEx(timer->hTimerQueue, INVALID_HANDLE_VALUE);

    timer->hTimerQueueTimer = NULL;
    timer->hTimerQueue = NULL;
    SetEvent(timer->winEvent);
     while (timer->isStart)		
		 mi_sleep(10);
	#elif MI_OS_APPLE
		dispatch_source_cancel(timer->_timer);
        timer->isStart = mifalse;

    #else
		 while (timer->isStart)			
			 mi_sleep(10);
		epoll_ctl(timer->efd, EPOLL_CTL_DEL, timer->timerfd, NULL);
		close(timer->efd);
		close(timer->timerfd);
		timer->timerfd = -1;
    #endif

#endif

	}

}

