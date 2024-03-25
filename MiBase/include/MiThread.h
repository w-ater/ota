#ifndef INCLUDE_MITHREAD_H_
#define INCLUDE_MITHREAD_H_
#include "MiUtil.h"
typedef void             *LpVoid;
typedef unsigned (*FpRunThread)(LpVoid lpParameter);

#if BASE_POSIX
    #include <pthread.h>
    #define mi_thread_create pthread_create
    #define mi_thread_t pthread_t
    #define mi_thread_mutex_t pthread_mutex_t
    #define mi_thread_cond_t pthread_cond_t
    #define mi_thread_join pthread_join
    #define mi_thread_exit pthread_exit
    #define mi_thread_detach pthread_detach
    #define mi_thread_equal pthread_equal
    #define mi_thread_mutex_lock pthread_mutex_lock
    #define mi_thread_mutex_unlock pthread_mutex_unlock
    #define mi_thread_cond_signal pthread_cond_signal
    #define mi_thread_cond_timedwait pthread_cond_timedwait
    #define mi_thread_cond_wait pthread_cond_wait
    #define mi_thread_mutex_init pthread_mutex_init
    #define mi_thread_mutex_destroy pthread_mutex_destroy
    #define mi_thread_cond_init pthread_cond_init
    #define mi_thread_cond_destroy pthread_cond_destroy
#endif


#if WIN32
		#include <windows.h>

		typedef HANDLE mi_thread_t;
		typedef CRITICAL_SECTION mi_thread_mutex_t;
		typedef struct {
                  HANDLE waiting_sem;
                  HANDLE received_sem;
                  HANDLE signal_event;
		} mi_thread_cond_t;
        #ifdef __cplusplus
        extern "C"{
        #endif
                    int mi_thread_create(mi_thread_t* const thread, const void* attr,void* (*startfn)(void*), void* arg);
                    int mi_thread_join(mi_thread_t thread, void** value_ptr);
                    int mi_thread_mutex_init(mi_thread_mutex_t* const mutex, void* mutexattr);
                    int mi_thread_mutex_lock(mi_thread_mutex_t* const mutex);
                    int mi_thread_mutex_unlock(mi_thread_mutex_t* const mutex);
                    int mi_thread_mutex_destroy(mi_thread_mutex_t* const mutex);
                    int mi_thread_cond_destroy(mi_thread_cond_t* const condition);
                    int mi_thread_cond_init(mi_thread_cond_t* const condition, void* cond_attr);
                    int mi_thread_cond_signal(mi_thread_cond_t* const condition);
                    int mi_thread_cond_wait(mi_thread_cond_t* const condition, mi_thread_mutex_t* const mutex);
        #ifdef __cplusplus
        }
        #endif
#endif



int createThread(FpRunThread fun,LpVoid userdata);
#endif 
