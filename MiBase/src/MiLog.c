#include "MiLog.h"
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>





#if !(MI_ANDROID || MI_IOS)
#define MI_Enable_Logfile 0
#else
#define MI_Enable_Logfile 1
#endif

#if WIN32
#include <io.h>
#ifdef _MSC_VER
#include <direct.h>
#endif
#else
#include <sys/time.h>
#endif

int32_t g_hasLogFile=0;
int32_t g_logLevel= MI_LOG_TRACE;

#if Mi_Enable_Logfile
FILE *g_fmsg = NULL;
#endif

static char const *MI_LOG_LEVEL_NAME[] = { "FATAL", "ERROR", "WARNING",
		"INFO", "DEBUG", "TRACE" };

void mi_setCLogFile(int32_t isSetLogFile) 
{

#if Mi_Enable_Logfile
	if (g_hasLogFile)
		return;
    g_hasLogFile = isSetLogFile;
	if (isSetLogFile&&g_fmsg==NULL) {
		char file1[300];
		mi_memset(file1, 0, 300);
		char file_path_getcwd[255];
        mi_memset(file_path_getcwd, 0, 255);
#ifdef _MSC_VER
        if (_getcwd(file_path_getcwd, 255)) {
#else
        if (getcwd(file_path_getcwd, 255)) {
#endif
			mi_sprintf(file1, "%s/mi_log.log", file_path_getcwd);
			mi_setCLogFile2(mitrue, file1);

		}

	}
#endif

}


void mi_setCLogFile2(int32_t isSetLogFile, char *fullpathfile) {
#if Mi_Enable_Logfile
	g_hasLogFile = isSetLogFile;
	if (g_fmsg == NULL)
		g_fmsg = fopen(fullpathfile, "wb+");
#endif
}

void mi_closeCLogFile() {
#if Mi_Enable_Logfile
	if (g_fmsg)
		fclose(g_fmsg); 
	g_fmsg = NULL;
#endif
}

void mi_clog(int32_t level, const char *fmt, ...) {
	if (level > g_logLevel)		return;
	char buf[4096];
	mi_memset(buf, 0, 4096);
	va_list args;
	va_start(args, fmt);

	mi_vsnprintf(buf, 4095, fmt, args);
	va_end(args);


    struct tm* ntm=NULL;
    if(level==MI_LOG_ERROR){
        time_t t_now=time(NULL);
        ntm=localtime(&t_now);
        mi_printf("[%02d:%02d:%02d] MI %s: %s\n",ntm->tm_hour,ntm->tm_min,ntm->tm_sec,MI_LOG_LEVEL_NAME[level], buf);

    }else{
         mi_printf("MI %s: %s\n",MI_LOG_LEVEL_NAME[level], buf);
    }
#if MI_Enable_Logfile
	if (g_hasLogFile) {

		char sf[4196];
		mi_memset(sf, 0, 4196);
        int32_t sfLen=0;
        if(level==MI_LOG_ERROR&&ntm)
             sfLen = mi_sprintf(sf, "[%02d:%02d:%02d] MI %s: %s\n",ntm->tm_hour,ntm->tm_min,ntm->tm_sec, MI_LOG_LEVEL_NAME[level], buf);
        else
             sfLen = mi_sprintf(sf, "MI %s: %s\n", MI_LOG_LEVEL_NAME[level], buf);
		if (g_fmsg){
			fwrite(sf, sfLen, 1, g_fmsg);
			fflush(g_fmsg);
		}
	}
#endif
    ntm=NULL;

}
#define MI_Log_Cachesize 1024*12
#define MI_Log_Cachesize2 MI_Log_Cachesize+256
void mi_clog2(int32_t level, const char *fmt, ...) {
	if (level > g_logLevel)		return;
	char buf[MI_Log_Cachesize];
	mi_memset(buf, 0, MI_Log_Cachesize);
	va_list args;
	va_start(args, fmt);

	mi_vsnprintf(buf, MI_Log_Cachesize, fmt, args);
	va_end(args);


    struct tm* ntm=NULL;
    if(level== MI_LOG_ERROR){
        time_t t_now=time(NULL);
        ntm=localtime(&t_now);
		mi_printf("[%02d:%02d:%02d] MI %s: %s\n",ntm->tm_hour,ntm->tm_min,ntm->tm_sec, MI_LOG_LEVEL_NAME[level], buf);

    }else{
		mi_printf("MI %s: %s\n", MI_LOG_LEVEL_NAME[level], buf);
    }
#if MI_Enable_Logfile
	if (g_hasLogFile) {

		char sf[MI_Log_Cachesize2];
		mi_memset(sf, 0, MI_Log_Cachesize);
        int32_t sfLen=0;
        if(level== MI_LOG_ERROR&&ntm)
             sfLen = mi_sprintf(sf, "[%02d:%02d:%02d] MI %s: %s\n",ntm->tm_hour,ntm->tm_min,ntm->tm_sec, MI_LOG_LEVEL_NAME[level], buf);
        else
             sfLen = mi_sprintf(sf, "MI %s: %s\n", MI_LOG_LEVEL_NAME[level], buf);
		if (g_fmsg){
			fwrite(sf, sfLen, 1, g_fmsg);
			fflush(g_fmsg);
		}

	}
#endif
    ntm=NULL;

}
int32_t mi_error_wrap(int32_t errcode, const char *fmt, ...) {
	char buf[4096];
	mi_memset(buf, 0, 4096);
	va_list args;
	va_start(args, fmt);
	mi_vsnprintf(buf, 4095, fmt, args);
	va_end(args);

    time_t t_now=time(NULL);
    struct tm* ntm=localtime(&t_now);
#if MI_ANDROID
    mi_error("MI Error(%d): %s\n",  errcode,buf);
#else
    mi_printf("MI Error(%d): %s\n",  errcode,buf);
#endif

#if MI_Enable_Logfile
	if (g_hasLogFile) {

		char sf[4196];
		mi_memset(sf, 0, 4196);
        int32_t sfLen = mi_sprintf(sf, "[%02d:%02d:%02d] mi Error(%d): %s\n",ntm->tm_hour,ntm->tm_min,ntm->tm_sec, errcode, buf);
    	if (g_fmsg){
    			fwrite(sf, sfLen, 1, g_fmsg);
    			fflush(g_fmsg);
    		}
	}
#endif
    ntm=NULL;
	return errcode;
}

void mi_clogf(int32_t level, const char *fmt, ...) 
{
    if (level > g_logLevel)	
		return;
	char buf[4096];
	mi_memset(buf, 0, 4096);
	int32_t len = 0;
	va_list args;
	va_start(args, fmt);
	len = mi_vsnprintf(buf, 4095, fmt, args);
	va_end(args);

	mi_printf("%s",buf);
#if MI_Enable_Logfile
	if (g_hasLogFile) {
		if (g_fmsg){
	    			fwrite(buf, len, 1, g_fmsg);
	    			fflush(g_fmsg);
	    }
	}
#endif
}
void mi_clogf2(int32_t level, const char *fmt, ...) {
    if (level > g_logLevel)	return;
	char buf[MI_Log_Cachesize];
	mi_memset(buf, 0, MI_Log_Cachesize);
	int32_t len = 0;
	va_list args;
	va_start(args, fmt);
	len = mi_vsnprintf(buf, MI_Log_Cachesize, fmt, args);
	va_end(args);

	mi_printf("%s",buf);
#if MI_Enable_Logfile
	if (g_hasLogFile) {
		if (g_fmsg){
	    			fwrite(buf, len, 1, g_fmsg);
	    			fflush(g_fmsg);
	    }
	}
#endif
}

void mi_setCLogLevel(int32_t plevel) {
	g_logLevel = plevel;
	if (g_logLevel > MI_LOG_TRACE)
		g_logLevel = MI_LOG_TRACE;
}

