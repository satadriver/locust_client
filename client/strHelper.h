#pragma once

#include <iostream>
#include <windows.h>

using namespace std;

std::string& getPathFileName(std::string& path, std::string& name);

std::string& wstring2string(std::wstring& wstr, std::string& astr);

std::wstring& string2wstring(std::string& astr, std::wstring& wstr);

int binarySearch(const char* data, int size, const char* tag, int tagsize);

int removeChar(string& str, char c);

string removeSpace(string data);