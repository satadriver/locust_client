

#include "shell.h"

#include "utils.h"



int __stdcall shell(const char * cmd) {
	int ret = 0;

	wchar_t wstrcmd[1024];

	char command[1024];

	wsprintfA(command, "cmd /c %s > %s", cmd, CMD_RESULT_FILENAME);

	ret = mbstowcs(wstrcmd, command, sizeof(wstrcmd) / sizeof(wchar_t));

	DWORD result = 0;

	ret = commandline(wstrcmd, TRUE, FALSE, &result);

	return ret;
}



int runShell(const char* cmd) {
	HANDLE ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)shell, (LPVOID)cmd, 0, 0);
	if (ht)
	{
		CloseHandle(ht);
	}
	return 0;
}


int commandline(WCHAR* szparam, int wait, int show, DWORD* ret) {
	int result = 0;

	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	DWORD processcode = 0;
	DWORD threadcode = 0;

	si.cb = sizeof(STARTUPINFOW);
	si.lpDesktop = (WCHAR*)L"WinSta0\\Default";
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = show;
	DWORD dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;

	result = CreateProcessW(0, szparam, 0, 0, 0, 0, 0, 0, &si, &pi);
	int errorcode = GetLastError();
	if (result) {
		if (wait)
		{
			WaitForSingleObject(pi.hProcess, INFINITE);
			GetExitCodeThread(pi.hProcess, &threadcode);
			GetExitCodeProcess(pi.hProcess, &processcode);
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	runLog(L"[mytestlog]command:%ws result:%d process excode:%d thread excode:%d errorcode:%d\r\n",
		szparam, result, processcode, threadcode, errorcode);
	return result;
}