#include "MiFile.h"


#ifdef _WIN32
#include <shlobj.h>
#else
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <dlfcn.h>

#endif



int  MiIsExist(const char* Path)
{
	if (strlen(Path)<1)
		return 0;
#ifdef _WIN32

	WIN32_FIND_DATAA Info;
	strcpy(Info.cFileName, Path);
	//::_tcs
	HANDLE h = FindFirstFileA(Path, &Info);
	if (h == INVALID_HANDLE_VALUE)
	{
		FindClose(h);
		return 0;
	}
	FindClose(h);
	return 1;

#else
	if (access(Path, F_OK) == 0)
		return 1;
	return 0;
#endif
}