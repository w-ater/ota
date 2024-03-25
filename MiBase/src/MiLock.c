#include "MiLock.h"

void milock_ini(MiLock* lock)
{
#ifdef WIN32
	mi_thread_mutex_init(lock, 0);
#endif

#ifdef POSIX_API___
	pthread_mutexattr_t mutex_attribute;
	pthread_mutexattr_init(&mutex_attribute);
	pthread_mutexattr_settype(&mutex_attribute, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&lock->lock, &mutex_attribute);
	pthread_mutexattr_destroy(&mutex_attribute);
#endif
}


void milock_lock(MiLock* lock)
{
	mi_thread_mutex_lock(&lock->lock);
}
void milock_unlock(MiLock* lock)
{
	mi_thread_mutex_unlock(&lock->lock);
}
void milock_destroy(MiLock* lock)
{
	mi_thread_mutex_destroy(&lock->lock);
}