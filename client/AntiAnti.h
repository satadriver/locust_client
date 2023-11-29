#pragma once


#pragma once

#include <windows.h>


int suicide();


int __stdcall attachSelf(VOID* param);

class Debug {
public:
	static int isDebugged();

	static int __stdcall attach();
};