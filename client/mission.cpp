
#include <windows.h>
#include "mission.h"

char* buildCmd(CONST char* data, int datalen, int type) {
	char* buf = new char[datalen + sizeof(MY_CMD_PACKET) + 16];
	MY_CMD_PACKET* mypack = (MY_CMD_PACKET*)buf;
	mypack->len = datalen;
	mypack->type = type;
	memcpy(mypack->value, data, datalen);
	return buf;
}