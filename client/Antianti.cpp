
#include "antianti.h"
#include <windows.h>
#include "utils.h"


int __stdcall attachSelf(VOID* param) {
	DWORD pid = GetCurrentProcessId();
	DebugActiveProcess((DWORD)pid);
	int e = TRUE;
	while (e)
	{
		DEBUG_EVENT MyDebugInfo;
		e = WaitForDebugEvent(&MyDebugInfo, INFINITE);
		switch (MyDebugInfo.dwDebugEventCode)
		{
		case EXIT_PROCESS_DEBUG_EVENT:
		{
			e = FALSE;
			break;
		}
		}
		if (e) {
			ContinueDebugEvent(MyDebugInfo.dwProcessId, MyDebugInfo.dwThreadId, DBG_CONTINUE);
		}
	}
	return 0;
}



int Debug::isDebugged()
{
#ifdef _DEBUG
	return FALSE;
#endif

#ifndef _WIN64
	int result = 0;
	__asm
	{
		mov eax, fs: [30h]
		// 控制堆操作函数的工作方式的标志位
		mov eax, [eax + 68h]
		// 操作系统会加上这些标志位:FLG_HEAP_ENABLE_TAIL_CHECK, FLG_HEAP_ENABLE_FREE_CHECK and FLG_HEAP_VALIDATE_PARAMETERS
		// 并集是x70
		and eax, 0x70
		mov result, eax
	}

	return result != 0;
#else
	return IsDebuggerPresent();
#endif
}

int __stdcall Debug::attach() {
	HANDLE ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)attachSelf, 0, 0, 0);
	if (ht)
	{
		CloseHandle(ht);
	}
	return TRUE;
}




int suicide() {
	ExitProcess(0);
	DWORD hp = (DWORD)GetCurrentProcessId();
	TerminateProcess((HANDLE)hp, 0);
	exit(0);
	abort();
	atexit(0);
	while (1)
	{
		Sleep(-1);
	}
	return 0;
}