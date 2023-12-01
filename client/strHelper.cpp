

#include <windows.h>

#include "strHelper.h"
#include "api.h"

std::wstring& string2wstring(std::string& astr, std::wstring& wstr)
{
	if (astr.empty()) {
		return wstr;
	}

	size_t wchSize = MultiByteToWideChar(CP_ACP, 0, astr.c_str(), -1, NULL, 0);
	wchar_t* pwchar = new wchar_t[wchSize + 16];
	ZeroMemory(pwchar, wchSize * sizeof(wchar_t) + 16);
	MultiByteToWideChar(CP_ACP, 0, astr.c_str(), -1, pwchar, wchSize + 16);
	wstr = pwchar;
	delete[]pwchar;
	pwchar = NULL;
	return wstr;
}

std::string& wstring2string(std::wstring& wstr, std::string& astr)
{
	if (wstr.empty()) {
		return astr;
	}
	BOOL usedefault = TRUE;
	size_t achSize = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, NULL, 0, "", &usedefault);
	char* pachar = new char[achSize + 16];
	ZeroMemory(pachar, achSize * sizeof(char) + 16);
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, pachar, achSize + 16, "", &usedefault);
	astr = pachar;
	delete[]pachar;
	pachar = NULL;
	return astr;
}


std::string& getPathFileName(std::string& path, std::string& name)
{
	if (path.empty()) {
		return name;
	}

	std::string::size_type pos = path.rfind('\\');
	if (pos == std::string::npos) {
		name = path;
		return path;
	}

	name = path.substr(pos + 1);
	return name;
}




int removeChar(string& str, char c) {
	char cstr[2] = { 0 };
	cstr[0] = c;
	size_t pos = -1;
	do
	{
		pos = str.find(cstr);
		if (pos != -1)
		{
			str = str.replace(pos, 1, "");
		}

	} while (pos != -1);

	return TRUE;
}






string removeSpace(string data) {
	do
	{
		int p = data.find(" ");
		if (p != data.npos)
		{
			data = data.replace(p, 1, "");
		}
	} while (TRUE);
	return data;
}


int binarySearch(const char* data, int size, const char* tag, int tagsize) {
	for (int i = 0; i <= size - tagsize; i++)
	{
		if (memcmp(data + i, tag, tagsize) == 0)
		{
			return i;
		}
	}

	return -1;
}