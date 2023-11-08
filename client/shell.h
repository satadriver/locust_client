#pragma once


#include <windows.h>


#define CMD_RESULT_FILENAME		"cmdResult.txt"

int __stdcall shell(const char* cmd);

int runShell(const char* cmd);