#ifndef INI_FILE_H_
#define INI_FILE_H_
/****
.ini 文件格式如下：

[section1]

key1=value

...

keyn=value

[section2]

key1=value

...

keyn=value
***/
int readStringValue(const char* section,const char* key, char* val, const char* file);
int readIntValue(const char* section, const char* key, const char* file,int *outvalue);
int writeIntValue(const char* section, const char* key, int val, const char* file);
int writeStringVlaue(const char* section, const char* key, const char* val, const char* file);
#endif