#pragma once

#include <windows.h>
#include <vector>
#include "http.h"

using namespace std;

class HttpsProto:public HttpProto
{
public:
	HttpsProto();
	HttpsProto(int action);

	HttpsProto(wchar_t* ip, unsigned short port, wchar_t* app);

	virtual ~HttpsProto();

	virtual bool postTest(string file, char* data, int filesize);

	virtual bool postHttpsFile(string filename);

	virtual bool postHttpsCmd(const char* cmd);


	virtual bool httpRequest(char* data, int datasize);

protected:
};

int uploadHttpsFile(const char* filename);