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
    //������ʱ�����þ���ʱ��.
    time_t expire;
    //�ӵ����õĶ�ʱ����ʱ����.
    int timeout;
    //��ʱ�ص�����.
    FpTimerFunc cb_func;
    //�ص���������.
    struct client_data* user_data;
} heap_timer;

typedef struct h_t_manager {
    //��ʱ��ָ������.
    struct heap_timer** array;
    //��ǰ��ʱ������֧�ֵ����ʱ������.
    int capacity;
    //��ǰ��ʱ�������ϵĶ�ʱ������.
    int cur_size;
} h_t_manager;


void        ht_init_manager(h_t_manager* tmanager, int cap);
heap_timer* ht_add_timer(h_t_manager* tmanager, int timeout, FpTimerFunc func, void* userdata);
int         ht_del_timer(h_t_manager* tmanager, heap_timer* timer);
void        ht_tick(h_t_manager* tmanager);
#endif