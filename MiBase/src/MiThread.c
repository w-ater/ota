#include "MiThread.h"
#if WIN32
#include <process.h>


typedef struct{
    void* (*startfn)(void*);
    void* user;
}MiThreadPara;



DWORD WINAPI mi_thread_beginFn2( LPVOID lpParam ){
    MiThreadPara* pThis = (MiThreadPara*)lpParam;
    if(pThis){
        pThis->startfn(pThis->user);
    }
    mi_free(pThis);
    return 0;
}

 int mi_thread_create(mi_thread_t* const thread, const void* attr,
                          void* (*startfn)(void*), void* arg) {
  (void)attr;
  MiThreadPara* para=(MiThreadPara*)mi_calloc(sizeof (MiThreadPara),1);
   para->user=arg;
   para->startfn=startfn;

   *thread = (mi_thread_t)CreateThread(
               NULL,                   // default security attributes
               0,                      // use default stack size
               mi_thread_beginFn2,       // thread function name
               para,          // argument to thread function
               0,                      // use default creation flags
               NULL);   // returns the thread identif
  if (*thread == NULL) return 1;
 // SetThreadPriority(*thread, THREAD_PRIORITY_ABOVE_NORMAL);
  return 0;
}

 int mi_thread_join(mi_thread_t thread, void** value_ptr) {
  (void)value_ptr;
  return (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0 ||
          CloseHandle(thread) == 0);
}

// Mutex
 int mi_thread_mutex_init(mi_thread_mutex_t* const mutex, void* mutexattr) {
  (void)mutexattr;
  InitializeCriticalSection(mutex);
  return 0;
}

 int mi_thread_mutex_lock(mi_thread_mutex_t* const mutex) {
  EnterCriticalSection(mutex);
  return 0;
}

 int mi_thread_mutex_unlock(mi_thread_mutex_t* const mutex) {
  LeaveCriticalSection(mutex);
  return 0;
}

 int mi_thread_mutex_destroy(mi_thread_mutex_t* const mutex) {
  DeleteCriticalSection(mutex);
  return 0;
}

// Condition
 int mi_thread_cond_destroy(mi_thread_cond_t* const condition) {
  int err = 1;
  err &= (CloseHandle(condition->waiting_sem) != 0);
  err &= (CloseHandle(condition->received_sem) != 0);
  err &= (CloseHandle(condition->signal_event) != 0);
  return !err;
}

 int mi_thread_cond_init(mi_thread_cond_t* const condition, void* cond_attr) {
  (void)cond_attr;
  condition->waiting_sem = CreateSemaphore(NULL, 0, 1, NULL);
  condition->received_sem = CreateSemaphore(NULL, 0, 1, NULL);
  condition->signal_event = CreateEvent(NULL, FALSE, FALSE, NULL);
  if (condition->waiting_sem == NULL ||
      condition->received_sem == NULL ||
      condition->signal_event == NULL) {
    mi_thread_cond_destroy(condition);
    return 1;
  }
  return 0;
}

 int mi_thread_cond_signal(mi_thread_cond_t* const condition) {
  int err = 1;
  if (WaitForSingleObject(condition->waiting_sem, 0) == WAIT_OBJECT_0) {
    // a thread is waiting in mi_thread_cond_wait: allow it to be notified
    err = SetEvent(condition->signal_event);
    // wait until the event is consumed so the signaler cannot consume
    // the event via its own mi_thread_cond_wait.
    err &= (WaitForSingleObject(condition->received_sem, INFINITE) !=
           WAIT_OBJECT_0);
  }
  return !err;
}

 int mi_thread_cond_wait(mi_thread_cond_t* const condition,
     mi_thread_mutex_t* const mutex) {
  int err=1;
            // note that there is a consumer available so the signal isn't dropped in
  // mi_thread_cond_signal
  if (!ReleaseSemaphore(condition->waiting_sem, 1, NULL))
    return 1;
  // now unlock the mutex so mi_thread_cond_signal may be issued
  mi_thread_mutex_unlock(mutex);
  err = (WaitForSingleObject(condition->signal_event, INFINITE) ==
        WAIT_OBJECT_0);
  err &= ReleaseSemaphore(condition->received_sem, 1, NULL);
  mi_thread_mutex_lock(mutex);
  return !err;
}
#endif





#include <memory.h>
#include <stdio.h>
#if defined(BASE_POSIX)
#include <sys/syscall.h>
#include <sys/prctl.h>
	
    #include <unistd.h>
    #include <pthread.h>
    #include <sys/time.h>
    #include <sys/times.h>
#endif

int createThread(FpRunThread fun,LpVoid userdata)
{
	#ifdef WIN32
			m_ThInfo.ThHandle   =  (HANDLE) _beginthreadex(NULL, NULL, RunThread, (LPVOID)this, 0,&m_ThInfo.ThreadAddr);
	#elif defined(BASE_POSIX)
      pthread_t     Tid_task;
      pthread_attr_t attr;
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
			pthread_create(&Tid_task, NULL, (void* (*)(void*))fun, userdata);
	#endif
return 0;
  }


  uint64_t  __GetTickCount64()
{
#ifdef _MSC_VER
	return ::GetTickCount64();
#else
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	uint64_t tick = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
	return tick;
#endif
}