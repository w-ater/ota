#!/bin/sh
/share/test/TX5112CV300_T8_V1R032C085/prebuilts/host/gcc/gcc-ts-10.3-2023.2-x86_64-arm-none-linux-uclibcgnueabihf/bin/arm-ts-linux-uclibcgnueabihf-gcc ota.c ini.c md5.c  -o otatest  -I./MiBase/include -lpthread -L./MiBase -lmibase
