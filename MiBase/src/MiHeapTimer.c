#include "MiHeapTimer.h"

static void percolate_down(h_t_manager* tmanager, int hole)
{
    heap_timer* temp = tmanager->array[hole];
    int flag = 0;
    int child = 0;
    for (; ((hole * 2 + 1) <= (tmanager->cur_size - 1)); hole = child)
    {
        flag = 0;
        child = hole * 2 + 1;

        //这里找出当前节点最小儿子节点
        if ((child < (tmanager->cur_size - 1))
            && (tmanager->array[child + 1]->expire)
            < tmanager->array[child]->expire)
        {
            ++child;
        }
        //比较待删除节点和最小儿子节点，若大于就交换
        if (tmanager->array[child]->expire < temp->expire)
        {
            //这里的交换其实该用内存拷贝比较好
            int tmp_expire = tmanager->array[hole]->expire;
            int tmp_timeout = tmanager->array[hole]->timeout;
            tmanager->array[hole]->expire = tmanager->array[child]->expire;
            tmanager->array[hole]->timeout = tmanager->array[child]->timeout;
            tmanager->array[child]->expire = tmp_expire;
            tmanager->array[child]->timeout = tmp_timeout;
        }
        else
        {
            break;
        }
        //新的下滤比较
        temp = tmanager->array[child];
        //tmanager->array[hole] = temp;
    }
}
//将堆数组的容量扩大1倍
static int resize(h_t_manager* tmanager)
{
    heap_timer** temp = (heap_timer**)
        malloc(2 * tmanager->capacity * sizeof(h_t_manager));

    int i = 0;
    for (; i < 2 * tmanager->capacity; ++i)
    {
        temp[i] = NULL;
    }
    if (!temp)
    {
        return -1;
    }
    tmanager->capacity = 2 * tmanager->capacity;
    for (i = 0; i < tmanager->cur_size; ++i)
    {
        temp[i] = tmanager->array[i];
        free(tmanager->array[i]);
        tmanager->array[i] = NULL;
    }
    tmanager->array = temp;

    return 0;
}
//
void ht_init_manager(h_t_manager* tmanager, int cap)
{
    tmanager->capacity = cap;
    tmanager->cur_size = 0;
    tmanager->array = (heap_timer**)malloc(cap * sizeof(h_t_manager));

    int i = 0;
    for (; i < cap; ++i)
    {
        tmanager->array[i] = NULL;
    }
}

//添加定时器.
heap_timer* ht_add_timer(h_t_manager* tmanager, int timeout, FpTimerFunc func,void* userdata)
{
    if (!tmanager || timeout <= 0)
    {
        return 0;
    }
    if (tmanager->cur_size >= tmanager->capacity)
    {
        resize(tmanager);
    }
    int hole = tmanager->cur_size++;
    int parent = 0;
    heap_timer* timer = (heap_timer*)malloc(sizeof(heap_timer));
    time_t tt = time(NULL);
    timer->expire = tt + timeout;
    timer->timeout = timeout;
    timer->user_data = userdata;
    timer->cb_func = func;
    for (; hole > 0; hole = parent)
    {
        parent = (hole - 1) / 2;
        if (tmanager->array[parent]->expire <= timer->expire)
        {
            break;
        }
        tmanager->array[hole] = tmanager->array[parent];
    }
    tmanager->array[hole] = timer;

    return timer;
}
int ht_del_timer(h_t_manager* tmanager, heap_timer* timer)
{
    if (!tmanager || !timer)
    {
        return -1;
    }
    timer->cb_func = NULL;
    return 0;
}
int ht_empty(h_t_manager* tmanager)
{
    return tmanager->cur_size == 0;
}

/*
heap_timer* top(h_t_manager* tmanager)
{
    if (empty(tmanager))
    {
        printf("!!!!!!!top->empty cur size\n");
        return NULL;
    }
    return tmanager->array[0];
}*/
int pop_timer(h_t_manager* tmanager)
{
    if (ht_empty(tmanager))
    {
        printf("!!!!!!!pop_timer->empty cur size\n");
        return -1;
    }
    if (tmanager->array[0])
    {
        free(tmanager->array[0]);
        tmanager->array[0] = NULL;
        tmanager->array[0] = tmanager->array[--tmanager->cur_size];
        percolate_down(tmanager, 0);
    }
    return 0;
}
void ht_tick(h_t_manager* tmanager)
{
    heap_timer* tmp = tmanager->array[0];
    time_t cur = time(NULL);
    while (!ht_empty(tmanager))
    {
        if (!tmp)
        {
            break;
        }
        if (tmp->expire > cur)
        {
            break;
        }
        if (tmanager->array[0]->cb_func)
        {
            printf("timer on time,heap:");
            int i = 0;
            for (; i < 10; i++)
            {
                if (tmanager->array[i])
                    printf("%d:%d ", i, tmanager->array[i]->timeout);
            }

            tmanager->array[0]->cb_func(tmanager->array[0]->user_data);
        }
        pop_timer(tmanager);
        tmp = tmanager->array[0];
        printf("after timer on time,heap:");
        int i = 0;
        for (; i < 10; i++)
        {
            if (tmanager->array[i])
                printf("%d:%d ", i, tmanager->array[i]->timeout);
        }
        printf("\n");
        if (tmanager->array[0])
            printf("the next alarm is:%d\n", (int)(tmanager->array[0]->timeout));
        printf("current timer count:%d\n", tmanager->cur_size);
    }
}