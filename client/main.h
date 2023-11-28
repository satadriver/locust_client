#pragma once


int init();


int clear();

int __stdcall fileMission();

int __stdcall cmdMission();

int restart(const char* newpath, const char* oldpath);

int __stdcall delFileProc(wchar_t* filename);