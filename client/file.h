#pragma once

#include <windows.h>
#include <vector>
#include <iostream>

using namespace std;



#define ALLFILES_FILENAME	"allFiles.dat"

#pragma pack(1)

typedef struct  
{
	int type;
	ULONGLONG size;
	FILETIME createtime;
	FILETIME accesstime;
	FILETIME modifytime;

	int fnlen;
	char filename[MAX_PATH];

}FILE_INFOMATION;

#pragma pack()

vector<FILE_INFOMATION> listDir(const char* PreStrPath);


int getDrivers(char* strDisk,int size);

int __stdcall getAllFiles();

class AllFiles {
	AllFiles();
	~AllFiles();
};