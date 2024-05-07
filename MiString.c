#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "MiString.h"
#include "MiMath.h"

void mi_destroy_strings(MiStrings* strs){
	if(strs==NULL||strs->str==NULL) 
		return;
    for (int32_t i=0;i<strs->vsize;i++)          
		free(strs->str[i]);

    free(strs->str);
}



int32_t mi_cstr_split(char *src, char *delim, MiStrings* istr)
{
	if(src==NULL||delim==NULL||istr==NULL) 
		return 1;
	 mi_memset(istr,0,sizeof(MiStrings));
	istr->capacity=10;
    istr->str=(char**)mi_calloc(istr->capacity*sizeof(char*),1);

    char  *p = NULL;

    istr->vsize = 0;
	p = strtok(src, delim);
	if(p==NULL) return 1;

	while(p){
		istr->str[istr->vsize]=(char*)mi_calloc(mi_strlen(p)+1,1);

		mi_memcpy(istr->str[istr->vsize],p,mi_strlen(p));
		istr->vsize++;
		if(istr->vsize>=istr->capacity){
            char** tmp=(char**)mi_calloc(istr->capacity*sizeof(char*),1);
			mi_memcpy(tmp,istr->str,istr->capacity*sizeof(char*));
			mi_free(istr->str);

            istr->str=(char**)mi_calloc((istr->capacity+10)*sizeof(char*),1);
			mi_memcpy(istr->str,tmp,istr->capacity*sizeof(char*));
			istr->capacity+=10;
			mi_free(tmp);
		}
		p = strtok(NULL, delim);
	}


    return mi_ok;
}

void mi_itoa(int32_t num,char* data,int32_t n){
	mi_sprintf(data,"%d",num);
}

void mi_itoa2(uint32_t num,char* data,int32_t n){
	mi_sprintf(data,"%u",num);
}

int32_t mi_get_line(char* buf,char *line, int32_t line_size)
{
	char* q=line;
	char ch;
    for (int32_t i=0;i<line_size;i++) {
    	ch=buf[i];
        if (ch == '\n') {
             if (q > line && q[-1] == '\r')
                 q--;
             *q = '\0';

             return 0;
         } else {
             if ((q - line) < line_size - 1)
                 *q++ = ch;
         }
    }
    return 1;
}


int32_t mi_cstr_strcmp(char* str1,char* str2){
	int32_t len=mi_strlen(str1);
	for(int32_t i=0;i<len;i++)
	{
		if(mi_tolower(str1[i])!=mi_tolower(str2[i])) 
			return 1;
	}
	return 0;
}

void mi_cstr_random(int32_t len,char* data) {
	if(data==NULL) return;
	static char* random_table ="01234567890123456789012345678901234567890123456789abcdefghijklmnopqrstuvwxyz";

	for (int32_t i = 0; i < len; ++i) {
		data[i]= random_table[mi_random() %mi_strlen(random_table)];
	}
}

void mi_cint32_random(int32_t len,char* data) {
	if(data==NULL) return;
	static char* random_int32_table ="01234567890123456789012345678901234567890123456789";

	for (int32_t i = 0; i < len; ++i) {
		data[i]= random_int32_table[mi_random() % mi_strlen(random_int32_table)];
	}
}

void mi_cstr_replace(char *str,char* dst, char *macth, char *rep)
{
	if(str==NULL||dst==NULL||macth==NULL||rep==NULL) return;
  char *p=NULL,*p1=NULL;

  if(!(p = mi_strstr(str, macth)))  {// Is 'orig' even in 'str'?
	  mi_strcpy(dst,str);
    return;
  }
  int32_t dstlen=p-str;
  int32_t replen= mi_strlen(rep);
  int32_t origlen= mi_strlen(macth);
  mi_memcpy(dst,str,dstlen);
  if(replen>0){
	  mi_memcpy(dst+dstlen,rep,replen);
	  dstlen+=replen;
  }
  while(p){
	  p1=p;
      p= mi_strstr(p1+origlen,macth);
	  if(p){
		  mi_memcpy(dst+dstlen,p1+origlen,p-p1-origlen);
		  dstlen+=p-p1-origlen;
		  if(replen>0){
			  mi_memcpy(dst+dstlen,rep,replen);
			  dstlen+=replen;
		  }
	  }else{
		  if(p1)     
			  mi_memcpy(dst+dstlen,p1+origlen,mi_strlen(str)-(p1-str)-origlen);
	  }
  }
}
int32_t mi_cstr_userfindindex(char* p,char c){
	int slen= mi_strlen(p);
	for(int32_t i=0;i<slen;i++){
		if(p[i]==c) 
			return i+1;//\n
	}
	return 0;
}
int32_t mi_cstr_userfindupindex(char* p,char c,int32_t n){

	for(int32_t i=0;i<n;i++){
		if(*(p-i)==c) 
			return i+1;//\n
	}
	return 0;
}

int32_t mi_cstr_isnumber(char* p,int32_t n){
	if(p==NULL) return -1;
	for(int32_t i=0;i<n;i++){
		if(p[i]>=48&&p[i]<=57) 
			return i;
	}
	return -1;
}


void    mi_int_string(MiString* str)
{
	if (str == 0)
		return;
	str->str = (char*)malloc(1024);
	str->capacity = 1024;
	str->pos = 0;
	memset(str->str,0, 1024);
}
void    mi_destroy_string(MiString* str)
{
	free(str->str);
	str->str = 0;
	str->capacity = 0;
	str->pos = 0;
}

void    mi_append_string(MiString* str,const char* nestr)
{
	int len = strlen(nestr);
	int sylen = str->capacity - str->pos;
	
	if (sylen < len)
	{
		int s = (len / 1024) * 1024 + 1024;
		char* newbuf = (char*)malloc(s);
		memset(newbuf, 0, s);
		memcpy(newbuf, str->str, str->pos);
		free(str->str);
		str->str = newbuf;
		str->capacity = s;
	}
	char* pos = str->pos + str->str;
	memcpy(pos, nestr, len);
	str->pos += len;
}