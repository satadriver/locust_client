#pragma once


#define VM_EVASION_DELAY 300


char* cpuBrand(char* strCpuBrand);

class VM {

public:

	static int isVM();

	static int getVmTick();

	static int delay(int seconds);
};