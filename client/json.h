#pragma once


#include <windows.h>

#include <iostream>

using namespace std;


#define JSON_TYPE_INT			1

#define JSON_TYPE_STRING		2

#define JSON_CONFIG_FILENAME				"config.json"

#define KEYNAME_DEAD_STATUS					"dead"
#define KEYNAME_HTTPS						"https"
#define KEYNAME_HEARTBEART_INTERVAL			"HBInterval"
#define KEYNAME_SERVER_IP					"serverip"
#define KEYNAME_FILE_SIZE					"filesize"

class MyJson {
public:
	MyJson();

	MyJson(string fn);

	~MyJson();

	string fromFile(string fn);

	string insert(string k, string v, int t);

	int saveFile();

	string getjsonValue(string  key, int type,int *postion);

	string setjsonValue(string key, string  v, int type);

	string m_json;
};