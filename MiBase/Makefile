CC=/share/test/TX5112CV300_T8_V1R032C085/prebuilts/host/gcc/gcc-ts-10.3-2023.2-x86_64-arm-none-linux-uclibcgnueabihf/bin/arm-ts-linux-uclibcgnueabihf-gcc
CXX=/share/test/TX5112CV300_T8_V1R032C085/prebuilts/host/gcc/gcc-ts-10.3-2023.2-x86_64-arm-none-linux-uclibcgnueabihf/bin/arm-ts-linux-uclibcgnueabihf-g++
ar=$(AR)
#c
SRCS =
#Sļ 
SRSS =
#c++ļ
SRCPPS =

DESP = 

PlatDef= -D BASE_POSIX
ifeq ($(DevType),Android/)
PlatDef+= -D BASE_ANDROID
else ifeq ($(DevType),IOS/)
PlatDef+= -D BASE_IOS 
else
PlatDef+= -D BASE_LINUX -D OS_LINUX
endif

SrcDir=$(PlatDef) $(STD_DIR)  -I./include 

LDFLAGS=$(BaseLibDir) 

#c++
CXXFLAGS=$(CompileOpion) -std=c++11   $(BaseDir) $(SrcDir)
#c 
CFLAGS=$(CompileOpion) $(BaseDir)  $(SrcDir)
CPPFLAGS= $(CXXFLAGS)
#汇编
ASFLAGS=

#cpp 代码
SRCPPS= 

#comm
SRCS =

#c 代码
SRCS = ./src/MiBuffer.o \
	./src/MiEndian.o \
	./src/MiFile.o \
	./src/MiHeapTimer.o \
	./src/MiLock.o \
	./src/MiLog.o \
	./src/MiMath.o \
	./src/MiRbtree.o \
	./src/MiSocket.o \
	./src/MiSocketIP.o \
	./src/MiString.o \
	./src/MiThread.o \
	./src/MiTime.o \
	./src/MiVector.o

TARGET= libmibase.a
.PHONY: all clean  
   

$(TARGET): $(SRCPPS)  $(SRCS)
	$(ar) rcs $(TARGET)  $(SRCPPS) $(SRCS)
	mkdir -p ../output/$(DevType)$(CpuType)lib/
	cp -f $(TARGET) ../output/$(DevType)$(CpuType)lib/
	@echo '$(TARGET) done'
$(SRCPPS):%o:%cpp
	$(CXX)  $(CXXFLAGS)   -fvisibility=hidden -ffunction-sections -fdata-sections -Wl,--gc-sections  -c $< -o $@  
$(SRCS):%o:%c
	$(CC)  $(CFLAGS)   -fvisibility=hidden -ffunction-sections -fdata-sections -Wl,--gc-sections -c $< -o $@  
clean:
	rm -f *.o $(TARGET)  $(SRCPPS) $(SRCS) ../output/$(DevType)$(CpuType)lib/$(TARGET)
