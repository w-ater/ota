#!/bin/sh
gcc ota.c ini.c md5.c  -o otest  -I./MiBase/include -lpthread -L./MiBase -lmibase64

