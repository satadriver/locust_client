

#include <iostream>
#include <windows.h>
#include "FileHelper.h"
#include "utils.h"
#include "strHelper.h"
#include "api.h"


using namespace std;




int FileHelper::CheckFileExist(string filename) {
	HANDLE hFile = lpCreateFileA((char*)filename.c_str(), GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		int err = GetLastError();
		if (err == 32 || err == 183)
		{
			return TRUE;
		}
		return FALSE;
	}
	else {
		CloseHandle(hFile);
		return TRUE;
	}
}


int FileHelper::CheckPathExist(string path) {
	if (path.back() != '\\')
	{
		path.append("\\");
	}
	path.append("*.*");

	WIN32_FIND_DATAA stfd;
	HANDLE hFind = lpFindFirstFileA((char*)path.c_str(), &stfd);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		int err = GetLastError();
		if (err == 32 || err == 183)
		{
			return TRUE;
		}
		return FALSE;
	}
	else {
		lpFindClose(hFind);
		return TRUE;
	}
}





int FileHelper::fileReader(const char* filename, char** data, int* datasize) {
	if (data == 0 || datasize == 0)
	{
		return FALSE;
	}
	int result = 0;
	HANDLE hf = lpCreateFileA(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0);
	if (hf == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD sizehigh = 0;
	size_t filesize = lpGetFileSize(hf, &sizehigh);
	if (sizehigh)
	{
		CloseHandle(hf);
		return FALSE;
	}

	int readsize = 0;

	if (*data == 0 || *datasize == 0)
	{
		*data = new char[filesize + 1024];
		if (*data == 0)
		{
			CloseHandle(hf);
			return FALSE;
		}
		readsize = filesize;
	}
	else {
		if (*datasize - 2 < 4)
		{
			CloseHandle(hf);
			return FALSE;
		}
		readsize = (*datasize - filesize >= 2) ? filesize : (*datasize - 2);
	}

	DWORD cnt = 0;
	result = lpReadFile(hf, *data, readsize, &cnt, 0);
	CloseHandle(hf);
	if (result && cnt == readsize)
	{
		*(unsigned short*)(*data + readsize) = 0;
		*datasize = filesize;
		return readsize;
	}
	return FALSE;
}

int FileHelper::fileWriter(const char* filename,const char* data, int datasize, int opt) {
	if (data == 0 || datasize == 0)
	{
		return FALSE;
	}
	int result = 0;
	HANDLE hf = INVALID_HANDLE_VALUE;

	DWORD dispos = 0;
	if (opt == FILE_WRITE_NEW)
	{
		dispos = CREATE_ALWAYS ;
	}
	else{
		dispos = OPEN_ALWAYS;
	}

	int mode = GENERIC_WRITE;
	if (opt == FILE_WRITE_CHECK)
	{
		mode |= GENERIC_READ;
	}

	hf = lpCreateFileA(filename, mode, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, dispos, 0, 0);
	if (hf == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD sizehigh = 0;
	size_t filesize = lpGetFileSize(hf, &sizehigh);

	DWORD cnt = 0;
	if (opt == FILE_WRITE_CHECK)
	{
		char* buffer = new char[filesize+256];
		result = lpReadFile(hf, buffer, filesize, &cnt, 0);
		if (result)
		{
			result = binarySearch(buffer, filesize, data, datasize);
			delete buffer;

			if (result != -1)
			{	
				CloseHandle(hf);
				return TRUE;
			}
		}
		else {
			CloseHandle(hf);
			delete[] buffer;
			return FALSE;
		}
	}

	if (dispos == OPEN_ALWAYS && (filesize > 0 || sizehigh > 0))
	{
		result = lpSetFilePointer(hf, filesize, (long*)&sizehigh, FILE_BEGIN);
		if (result == 0)
		{
			CloseHandle(hf);
			return FALSE;
		}
	}

	
	result = lpWriteFile(hf, data, datasize, &cnt, 0);
	CloseHandle(hf);
	if (result && cnt == datasize)
	{
		return datasize;
	}
	return FALSE;
}

LPVOID FileMapping(const WCHAR* name, DWORD size)
{
	LPVOID lpMapAddr = 0;
	HANDLE m_hMapFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
	if (m_hMapFile)
	{
		lpMapAddr = MapViewOfFile(m_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	}
	else
	{
		m_hMapFile = CreateFileMappingW((HANDLE)0xFFFFFFFF, NULL, PAGE_EXECUTE_READWRITE, 0, size, name);
		if (m_hMapFile)
		{
			lpMapAddr = MapViewOfFile(m_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);

			//FlushViewOfFile(lpMapAddr, strTest.length() + 1);
		}
	}

	return lpMapAddr;
}