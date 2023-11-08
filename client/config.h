#pragma once


#include<windows.h>
#include "http.h"
#include "https.h"


#pragma pack(1)

typedef struct
{
	DWORD ip;
	DWORD hbi;
	DWORD fzLimit;
	DWORD bHttps;
	char path[MAX_PATH];
}PROGRAM_PARAMS;

#pragma pack()

class Config
{
public:
	Config();
	~Config();

	static int getConfig();

};