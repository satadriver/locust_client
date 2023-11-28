

#include "vm.h"

#include "FileHelper.h"
#include "shell.h"
#include "utils.h"


int VM::isVM() {

	int ret = 0;

	int vmlabel = FALSE;

	do 
	{
		char syspath[MAX_PATH];
		int len = GetSystemDirectoryA(syspath, sizeof(syspath));
		syspath[len] = 0;
		string driverpath = string(syspath) + "\\drivers\\";

		ret = FileHelper::CheckFileExist(driverpath + "vmmouse.sys");		//vmmemctl.sys
		if (ret)
		{
			vmlabel = TRUE;
			break;
		}

		ret = FileHelper::CheckFileExist(driverpath + "VBoxMouse.sys");		//VBoxGuest
		if (ret)
		{
			vmlabel = TRUE;
			break;
		}
	
		const char* cmd = "sc query";
		shell(cmd);
		char* file = 0;
		int filesize = 0;
		ret = FileHelper::fileReader(CMD_RESULT_FILENAME, &file, &filesize);
		if (ret)
		{
			file[filesize] = 0;
			string vgauth = string("SERVICE_NAME: ") + "VGAuthService\r\n";
			string tool = string("SERVICE_NAME: ") + "VMTools\r\n";
			string vboxserv = string("SERVICE_NAME: ") + "VboxService\r\n";
		
			if (strstr(file, vgauth.c_str()) || strstr(file, tool.c_str()) || strstr(file, vboxserv.c_str()))
			{
				vmlabel = TRUE;
				break;
			}
		}

		cmd = "wmic path Win32_ComputerSystem get Model";
		shell(cmd);
		ret = FileHelper::fileReader(CMD_RESULT_FILENAME, &file, &filesize);
		if (ret)
		{
			file[filesize] = 0;
			const wchar_t * vm = L"VMware";
			const wchar_t* vb = L"VirtualBox";
			const wchar_t* vp = L"VirtualPC";
			if (wcsstr((wchar_t*)file, vm) || wcsstr((wchar_t*)file, vb) || wcsstr((wchar_t*)file, vp))
			{
				vmlabel = TRUE;
				break;
			}
		}
	
		DWORD pid = getPidByName("VGAuthService.exe");
		if (pid)
		{
			vmlabel = TRUE;
			break;
		}
		pid = getPidByName("vmtoolsd.exe");
		if (pid)
		{
			vmlabel = TRUE;
			break;
		}
		pid = getPidByName("VBoxService.exe");
		if (pid)
		{
			vmlabel = TRUE;
			break;
		}
		pid = getPidByName("VBoxTray.exe");
		if (pid)
		{
			vmlabel = TRUE;
			break;
		}

		HMODULE hdll = LoadLibraryA("sbiedll.dll");
		if (hdll)
		{
			vmlabel = TRUE;
			break;
		}

	} while (FALSE);

	if (ret)
	{
#ifdef _DEBUG

#else
// 		ExitProcess(0);
// 		exit(0);
#endif
	}
	return ret;
}


int VM::delay(int seconds) {

	ULONGLONG t1 = GetTickCount64() / 1000;
	ULONGLONG t2 = t1;
	do
	{
		t2 = GetTickCount64() / 1000;

		Sleep( 1000);

	} while (t2 - t1 < seconds);

	return 0;
}




int VM::getVmTick() {

	DWORD dt;
	ULONGLONG t;
	do
	{
		dt = GetTickCount() / 1000;

		t = GetTickCount64() / 1000;

		Sleep(VM_EVASION_DELAY*1000);
	} while (dt < VM_EVASION_DELAY || t < VM_EVASION_DELAY);

	return TRUE;
}






void executeCpuid(DWORD veax, DWORD* Regs)
{
#ifndef _WIN64
	DWORD deax;
	DWORD debx;
	DWORD decx;
	DWORD dedx;

	__asm
	{
		mov eax, veax; 将输入参数移入eax
		cpuid; 执行cpuid
		mov deax, eax; 以下四行代码把寄存器中的变量存入临时变量
		mov debx, ebx
		mov decx, ecx
		mov dedx, edx
	}

	Regs[0] = deax;
	Regs[1] = debx;
	Regs[2] = decx;
	Regs[3] = dedx;
#else
	return;
#endif
}


char* cpuBrand(char* strCpuBrand)
{
	strCpuBrand[0] = 0;

	char strcpu[256] = { 0 };
	DWORD Regs[4] = { 0 };
	DWORD BRANDID = 0x80000002;		// 从0x80000002开始，到0x80000004结束,用来存储商标字符串，48个字符
	for (DWORD i = 0; i < 3; i++)
	{
		executeCpuid(BRANDID + i, Regs);
		RtlMoveMemory(strcpu + i * 16, (char*)Regs, 16);
	}

	lstrcpyA(strCpuBrand, strcpu);

	return strCpuBrand;
}
