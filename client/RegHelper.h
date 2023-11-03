

#ifndef REGHELPER_H_H_H
#define REGHELPER_H_H_H

#include <windows.h>

DWORD getKeyValue(HKEY hMainKey, char* szSubKey, char* szKeyName, unsigned char* szKeyValue, int* buflen);

DWORD setKeyValueChar(HKEY hMainKey, char* szSubKey, char* szKeyName, char* szKeyValue);

DWORD setKeyValueDword(HKEY hMainKey, char* szSubKey, char* szKeyName, DWORD dwKeyValue);

int setRegBootRun(HKEY hMainKey, char* strPEResidence);


#endif