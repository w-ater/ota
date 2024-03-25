#ifndef __MILOG_H__
#define __MILOG_H__
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include "MiUtil.h"

#define MI_LOG_FATAL     0
#define MI_LOG_ERROR     1
#define MI_LOG_WARNING   2
#define MI_LOG_INFO      3
#define MI_LOG_DEBUG     4
#define MI_LOG_TRACE     5

int32_t mi_error_wrap(int32_t errcode, const char *fmt, ...);
void mi_clog(int32_t level, const char *fmt, ...);
void mi_clogf(int32_t level, const char *fmt, ...);
void mi_clogf2(int32_t level, const char *fmt, ...);
void mi_setCLogFile(int32_t isSetLogFile);
void mi_setCLogFile2(int32_t isSetLogFile, char *fullpathfile);
void mi_closeCLogFile();
void mi_setCLogLevel(int32_t plevel);


#define mi_fatal( fmt, ...)  mi_clog(0,fmt, ##__VA_ARGS__)
#define mi_error( fmt, ...)  mi_clog(1,fmt, ##__VA_ARGS__)
#define mi_warn( fmt, ...)   mi_clog(2,fmt, ##__VA_ARGS__)
#define mi_info( fmt, ...)   mi_clog(3,fmt, ##__VA_ARGS__)
#define mi_debug( fmt, ...)  mi_clog(4,fmt, ##__VA_ARGS__)


#define mi_debug2( fmt, ...)   mi_clogf(4,fmt, ##__VA_ARGS__)
#define mi_info2( fmt, ...)    mi_clogf(3,fmt, ##__VA_ARGS__)
#define mi_trace( fmt, ...)    mi_clogf(5,fmt, ##__VA_ARGS__)
#define mi_trace2( fmt, ...)   mi_clogf2(5,fmt, ##__VA_ARGS__)



#define mi_setLogLevel(x)      mi_setCLogLevel(x)
#define mi_setLogFile(x)       mi_setCLogFile(x)
#define mi_setLogFile2(x,y)    mi_setCLogFile2(x,y)
#define mi_closeLogFile        mi_closeCLogFile

#endif
