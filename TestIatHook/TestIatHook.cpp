// TestIatHook.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#undef NDEBUG
#include <cassert>
#include <iostream>

#include "ModernHook.h"

using namespace std;

using namespace ModernHook;


HANDLE WINAPI MyGetCurrentProcess()
{
	return NULL;
}

void TestHookEnable()
{
	IatHook<decltype(GetCurrentProcess)> hook(GetModuleHandle(NULL), "kernel32.dll", "GetCurrentProcess", MyGetCurrentProcess);
	hook.Enable();
	assert(GetCurrentProcess() == (HANDLE)NULL);
}

void TestHookDisable()
{
	IatHook<decltype(GetCurrentProcess)> hook(GetModuleHandle(NULL), "kernel32.dll", "GetCurrentProcess", MyGetCurrentProcess);
	hook.Enable();
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
	TestHookEnable();
	TestHookDisable();
	TestRaii();
	TestCallOrig();
	cout << "OK" << endl;

    return 0;
}
