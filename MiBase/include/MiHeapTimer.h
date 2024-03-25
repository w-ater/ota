#ifndef MiHeapTimer_H_
#define MiHeapTimer_H_

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <signal.h>
#include <time.h>

typedef void (*FpTimerFunc)(void* param);
typedef struct heap_timer 
{
    //单个定时器设置绝对时间.
    time_t expire;
    //加的设置的定时器到时秒数.
    int timeout;
    //到时回调函数.
    FpTimerFunc cb_func;
    //回调函数参数.
    struct client_data* user_data;
} heap_timer;

typedef struct h_t_manager {
    //定时器指针数组.
    struct heap_timer** array;
    //当前定时管理器支持的最大定时器个数.
    int capacity;
    //当前定时管理器上的定时器个数.
    int cur_size;
} h_t_manager;


void        ht_init_manager(h_t_manager* tmanager, int cap);
heap_timer* ht_add_timer(h_t_manager* tmanager, int timeout, FpTimerFunc func, void* userdata);
int         ht_del_timer(h_t_manager* tmanager, heap_timer* timer);
void        ht_tick(h_t_manager* tmanager);
#endif