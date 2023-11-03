#pragma once


#include <windows.h>


#define CMD_RESULT_FILENAME		"cmdResult.txt"

int __stdcall shell(char* cmd);

int runShell(char* cmd);