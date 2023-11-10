
#include <windows.h>

#include "http.h"
#include "https.h"

#include "config.h"
#include "public.h"

#include <iostream>
#include "json.h"


using namespace std;



Config::Config() {

}


Config::~Config() {

}

int Config::getConfig() {
	MyJson j(JSON_CONFIG_FILENAME);
	int pos = 0;

	int ret = 0;

	string dead = j.getjsonValue(KEYNAME_DEAD_STATUS, JSON_TYPE_STRING, &pos);
	if (dead != "") {
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
	g_httpsToggle = TRUE;

	string interval = j.getjsonValue(KEYNAME_HEARTBEART_INTERVAL, JSON_TYPE_STRING, &pos);
	if (interval != "")
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










