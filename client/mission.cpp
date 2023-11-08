
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



char* buildCmd2(CONST char* data1, int datalen1, int type1, const char* data2, int datalen2, int type2) {
	char* buf = new char[datalen1 + sizeof(MY_CMD_PACKET) + datalen2 + sizeof(MY_CMD_PACKET) + 16];
	MY_CMD_PACKET* mypack = (MY_CMD_PACKET*)buf;
	mypack->len = datalen1;
	mypack->type = type1;
	if (data1 && datalen1)
	{
		memcpy(mypack->value, data1, datalen1);
	}
	mypack = (MY_CMD_PACKET*)(buf + datalen1 + sizeof(MY_CMD_PACKET));
	mypack->len = datalen2;
	mypack->type = type2;
	if (data2 && datalen2)
	{
		memcpy(mypack->value, data2, datalen2);
	}
	return buf;
}