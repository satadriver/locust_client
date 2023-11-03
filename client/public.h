#pragma once

#include <windows.h>

#define HTTP_COMM_TYPE_FILE		1


#define  MAX_UPLOAD_FILESIZE			0X4000000

#define HEART_BEAT_INTERVAL				30000

#define HEART_BEAT_TEST_INTERVAL		100

#define MY_USERAGENT			L"myUserAgent"

extern "C" DWORD g_ip;

extern "C" DWORD g_httpsToggle;

extern "C" char g_uuid[64];

extern "C" int g_uuid_len;

extern int g_interval;

extern int g_fsize_limit;