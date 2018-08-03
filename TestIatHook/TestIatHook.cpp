// TestIatHook.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <assert.h>

#include "ModernHook.h"

using namespace ModernHook;


static HANDLE WINAPI MyGetCurrentProcess()
{
	return NULL;
}

void TestHook()
{
	IatHook<decltype(GetCurrentProcess)> hook(GetModuleHandle(NULL), "kernel32.dll", "GetCurrentProcess", MyGetCurrentProcess);
	hook.Enable();
	assert(GetCurrentProcess() == (HANDLE)NULL);
	hook.Disable();
	assert(GetCurrentProcess() != (HANDLE)NULL);
}

void TestRaii()
{
	{
		IatHook<decltype(GetCurrentProcess)> hook(GetModuleHandle(NULL), "kernel32.dll", "GetCurrentProcess", MyGetCurrentProcess);
		hook.Enable();
	}
	assert(GetCurrentProcess() != (HANDLE)NULL);
}

void TestCallOrig()
{
	IatHook<decltype(GetCurrentProcess)> hook(GetModuleHandle(NULL), "kernel32.dll", "GetCurrentProcess", MyGetCurrentProcess);
	hook.Enable();
	assert(hook.CallOriginalFunction() != (HANDLE)NULL);
}


int main()
{
	TestHook();
	TestRaii();
	TestCallOrig();

    return 0;
}
