
#include "AntiDetect.h"
#include "AntiAnti.h"
#include "utils.h"

LONG __stdcall expHandler(_EXCEPTION_POINTERS* ExceptionInfo) 
{
	PEXCEPTION_RECORD record = ExceptionInfo->ExceptionRecord;

	PCONTEXT context = ExceptionInfo->ContextRecord;

	char info[1024];

	if (record->ExceptionCode == 0xC0000094)
	{
		//wsprintfA(info, "error code:%x", record->ExceptionCode);
		//MessageBoxA(0, info, info, MB_OK);
		opLog("error code:%x\r\n", record->ExceptionCode);

		//context->Rip += 8;
#ifdef _WIN64
		ULONG* lpdata = (ULONG*)(context->Rsp + 0x24);
#else
		ULONG* lpdata = (ULONG*)(context->Ebp - 0x10);
#endif
		*lpdata = 1;

		//record->ExceptionFlags = EXCEPTION_EXECUTE_HANDLER;
		
		//SetErrorMode(SEM_NOGPFAULTERRORBOX);

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	
	opLog("In debugging:%x\r\n", record->ExceptionCode);
	suicide();

	return FALSE;
}

int exceptTest() {

	int ret = 0;

	LPTOP_LEVEL_EXCEPTION_FILTER prev = SetUnhandledExceptionFilter(expHandler);
	if (prev)
	{
		//suicide();
	}

	int divided = 0;

	int divisor = 2;

	int remainder = divisor % 1;

#ifndef _DEBUG
	double quotient = divided / remainder;
#endif
	
	return ret;
}