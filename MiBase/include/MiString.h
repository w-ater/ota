
#ifndef INCLUDE_CSTRING_H_
#define INCLUDE_CSTRING_H_

#include "MiUtil.h"


typedef struct 
{
    int32_t capacity;
    int32_t pos;
    char* str;
}MiString;


//×Ö·û´®Êý×é.
typedef struct {
    int32_t capacity;
    int32_t vsize;
    char **str;
}MiStrings;

void    mi_int_string(MiString *str);
void    mi_destroy_string(MiString* str);
void    mi_append_string(MiString* str,const char* nestr);

void    mi_cint32_random(int32_t len,char* data);
void    mi_cstr_random(int32_t len,char* data);
int32_t mi_cstr_split(char *src, char *delim, MiStrings* istr);
void    mi_cstr_replace(char *str,char* dst, char *orig, char *rep);
void    mi_destroy_strings(MiStrings* strs);
int32_t mi_cstr_userfindindex(char* p,char c);
int32_t mi_cstr_userfindupindex(char* p,char c,int32_t n);
int32_t mi_cstr_isnumber(char* p,int32_t n);
int32_t mi_cstr_strcmp(char* str1,char* str2);
void    mi_itoa(int32_t num,char* data,int32_t n);
void    mi_itoa2(uint32_t num,char* data,int32_t n);
int32_t mi_get_line(char* buf,char *line, int32_t n);

#endif 
