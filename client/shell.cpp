

#include "shell.h"

#include "utils.h"



int __stdcall shell(char * cmd) {
	int ret = 0;

	wchar_t wstrcmd[1024];

	char command[1024];

	wsprintfA(command, "cmd /c %s > %s", cmd, CMD_RESULT_FILENAME);

	ret = mbstowcs(wstrcmd, command, sizeof(wstrcmd) / sizeof(wchar_t));

	delete cmd;

	DWORD result = 0;

	ret = commandline(wstrcmd, TRUE, FALSE, &result);

	return ret;
}



int runShell(char* cmd) {
	HANDLE ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)shell, cmd, 0, 0);
	if (ht)
	{
		CloseHandle(ht);
	}
	return 0;
}