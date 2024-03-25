#define _PARAM_GLOBALS_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ini.h"
#include "MiString.h"
#define SECTION_MAX_LEN 256
#define STRVALUE_MAX_LEN 6144
#define LINE_CONTENT_MAX_LEN 8192
#define bool    unsigned char
#define false   0
#define true    1
//read value from .ini
int IniReadValue(char* section, const char* key, char* val, const char* file)
{
    FILE* fp;
    int i = 0;
    int lineContentLen = 0;
    int position = 0;
    char lineContent[LINE_CONTENT_MAX_LEN+1];
    bool bFoundSection = false;
    bool bFoundKey = false;
    fp = fopen(file, "r");
    if(fp == NULL)
    {
        printf("%s: Opent file %s failed.\n", __FILE__, file);
        return 0;
    }
    while(feof(fp) == 0)
    {
        memset(lineContent, 0, LINE_CONTENT_MAX_LEN+1);
        fgets(lineContent, LINE_CONTENT_MAX_LEN, fp);
        if((lineContent[0] == ';') || (lineContent[0] == '\0') || (lineContent[0] == '\r') || (lineContent[0] == '\n'))
        {
            continue;
        }

        //check section
        if(strncmp(lineContent, section, strlen(section)) == 0)
        {
            bFoundSection = true;
            //printf("Found section = %s\n", lineContent);
            while(feof(fp) == 0)
            {
                memset(lineContent, 0, LINE_CONTENT_MAX_LEN+1);
                fgets(lineContent, LINE_CONTENT_MAX_LEN, fp);
                //check key
                if(strncmp(lineContent, key, strlen(key)) == 0)
                {
                    bFoundKey = true;
                    lineContentLen = strlen(lineContent);
                    //find value
                    for(i = strlen(key); i < lineContentLen; i++)
                    {
                        if(lineContent[i] == '=')
                        {
                            position = i + 1;
                            break;
                        }
                    }
                    if(i >= lineContentLen) break;
                    strncpy(val, lineContent + position, strlen(lineContent + position));
                    lineContentLen = strlen(val);
                    for(i = 0; i < lineContentLen; i++)
                    {
                        if((lineContent[i] == '\0') || (lineContent[i] == '\r') || (lineContent[i] == '\n'))
                        {
                            val[i] = '\0';
                            break;
                        }
                    }  
                }
                else if(lineContent[0] == '[') 
                {
                    break;
                }
            }
            break;
        }
    }
    if(!bFoundSection)
    {
        printf("No section = %s\n", section);
    }else if(!bFoundKey)
        {
            printf("No key = %s\n", key);
        }
    fclose(fp);
	return bFoundKey;
}

int readStringValue(const char* section,const char* key, char* val, const char* file)
{
	int pos = strlen(val);
	if(pos>0)
	memset(val, 0, pos + 1);
    char sect[SECTION_MAX_LEN+1];
    //printf("section = %s, key = %s, file = %s\n", section, key, file);
    if (section == NULL || key == NULL || val == NULL || file == NULL)
    {
        printf("%s: input parameter(s) is NULL!\n", __func__);
        return 0;
    }

    memset(sect, 0, SECTION_MAX_LEN+1);
    sprintf(sect, "[%s]", section);
    //printf("reading value...\n");
    int ret = IniReadValue(sect, key, val, file);
    pos = strlen(val);
	if (pos > 0)
	{
        int i=0;
        while ( pos>0&& i<3) {
             pos -= 1;
            if (val[pos] == '\n')
                val[pos] = 0;
            if (val[pos] == '\r')
                val[pos] = 0;
           i++;
        }


	}

    return ret;
}

int readIntValue(const char* section,const char* key, const char* file, int *outvalue)
{
    char strValue[STRVALUE_MAX_LEN+1];
    memset(strValue, '\0', STRVALUE_MAX_LEN+1);
    if(readStringValue(section, key, strValue, file) != 1)
    {
        printf("%s: error", __func__);
        return 0;
    }
	*outvalue = atoi(strValue);

	return 1;
}

void IniWriteValue(const char* section, const char* key, const char* val, const char* file)
{
    FILE* fp;
    int i = 0, n = 0, err = 0;
    int lineContentLen = 0;
    int position = 0;
    char lineContent[LINE_CONTENT_MAX_LEN+1];
    char strWrite[LINE_CONTENT_MAX_LEN+1];
    bool bFoundSection = false;
    bool bFoundKey = false;
    
    memset(lineContent, '\0', LINE_CONTENT_MAX_LEN+1);
    memset(strWrite, '\0', LINE_CONTENT_MAX_LEN+1);
    n = sprintf(strWrite, "%s=%s\n", key, val);
    fp = fopen(file, "r+");
    if(fp == NULL)
    {
        fp = fopen(file, "w+");
        if(fp==NULL)
       {
        printf("%s: Opent file %s failed.\n", __FILE__, file);
        return;
       }
    }
    MiString OldStr;
    mi_int_string(&OldStr);
    mi_append_string(&OldStr, section);
    mi_append_string(&OldStr, "\n");
	
    while(feof(fp) == 0)
    {
        memset(lineContent, 0, LINE_CONTENT_MAX_LEN+1);
        fgets(lineContent, LINE_CONTENT_MAX_LEN, fp);
        if((lineContent[0] == ';') || (lineContent[0] == '\0') || (lineContent[0] == '\r') || (lineContent[0] == '\n'))
        {
            continue;
        }
        //check section
        if(strncmp(lineContent, section, strlen(section)) == 0)
        {
            bFoundSection = true;
            while(feof(fp) == 0)
            {
                memset(lineContent, 0, LINE_CONTENT_MAX_LEN+1);
                fgets(lineContent, LINE_CONTENT_MAX_LEN, fp);
				
                //check key
                if(strncmp(lineContent, key, strlen(key)) == 0)
                {
                    bFoundKey = true;
                } else if(lineContent[0] == '[') 
                {
                    break;
                }
                else
                    mi_append_string(&OldStr, lineContent);

            }
            break;
        }
    }
    if(!bFoundSection)
	{
		fputs(OldStr.str, fp);
		fputs("\n", fp);
		printf("No section = %s\n", section);
	}else if(!bFoundKey)
	{
		fputs(strWrite, fp);
		printf("No key = %s\n", key);
	}
    fclose(fp);
	if (bFoundKey)
	{
		fp = fopen(file, "w");
        int index = OldStr.pos;
        if (index > 2)
        {
            index -= 1;
            fputs(OldStr.str, fp);
            if (OldStr.str[index] != '\n')
            {
                fputs("\n", fp);
            }
        }
		fputs(strWrite, fp);
		fclose(fp);
	}
    mi_destroy_string(&OldStr);
}

int writeStringVlaue(const char* section, const char* key, const char* val, const char* file)
{
    char sect[SECTION_MAX_LEN+1];
    //printf("section = %s, key = %s, file = %s\n", section, key, file);
    if (section == NULL || key == NULL || val == NULL || file == NULL)
    {
        printf("%s: input parameter(s) is NULL!\n", __func__);
        return 0;
    }

	if (strlen(val) > STRVALUE_MAX_LEN - 4)
		return 0;

	if (strlen(key) > SECTION_MAX_LEN - 1)
		return 0;

    memset(sect, '\0', SECTION_MAX_LEN+1);
    sprintf(sect, "[%s]", section);
    IniWriteValue(sect, key, val, file);
	return 1;
}

int writeIntValue(const char* section, const char* key, int val, const char* file)
{
    char strValue[STRVALUE_MAX_LEN+1];
    memset(strValue, '\0', STRVALUE_MAX_LEN+1);
    sprintf(strValue, "%-4d", val);
    
  return  writeStringVlaue(section, key, strValue, file);
}
