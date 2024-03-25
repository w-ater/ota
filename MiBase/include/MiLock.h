#ifndef mi_lock_h
#define mi_lock_h
#include "MiThread.h"
typedef struct MiLock
{
	mi_thread_mutex_t lock;
}MiLock;

void milock_ini(MiLock* lock);
void milock_lock(MiLock* lock);
void milock_unlock(MiLock* lock);
void milock_destroy(MiLock* lock);
#endif