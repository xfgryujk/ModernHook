#include "stdafx.h"

#include "ModernHook.h"

namespace ModernHook
{

void Hook::Enable()
{
	if (IsEnabled())
		return;
	DoEnable();
	SetIsEnabled(true);
}

void Hook::Disable()
{
	if (!IsEnabled())
		return;
	DoDisable();
	SetIsEnabled(false);
}


#ifndef _WIN64 // x86
InlineHook::JmpCode::JmpCode(uintptr_t srcAddr, uintptr_t dstAddr)
{
	SetAddress(srcAddr, dstAddr);
}

void InlineHook::JmpCode::SetAddress(uintptr_t srcAddr, uintptr_t dstAddr)
{
	relativeAddress = dstAddr - srcAddr - sizeof(JmpCode);
}
#else // x64
InlineHook::JmpCode::JmpCode(uintptr_t srcAddr, uintptr_t dstAddr)
{
	SetAddress(srcAddr, dstAddr);
}

void InlineHook::JmpCode::SetAddress(uintptr_t srcAddr, uintptr_t dstAddr)
{
	address = dstAddr;
}
#endif

InlineHook::InlineHook(void* _originalFunction, void* _hookFunction, bool enable) :
	originalFunction(_originalFunction),
	hookFunction(_hookFunction)
{
	memcpy(&originalCode, originalFunction, sizeof(originalCode));

	if (enable)
		Enable();
}

void InlineHook::DoEnable()
{
	JmpCode code((uintptr_t)originalFunction, (uintptr_t)hookFunction);
	DWORD oldProtect, oldProtect2;
	VirtualProtect(originalFunction, sizeof(JmpCode), PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(originalFunction, &code, sizeof(JmpCode));
	VirtualProtect(originalFunction, sizeof(JmpCode), oldProtect, &oldProtect2);
}

void InlineHook::DoDisable()
{
	DWORD oldProtect, oldProtect2;
	VirtualProtect(originalFunction, sizeof(JmpCode), PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(originalFunction, &originalCode, sizeof(originalCode));
	VirtualProtect(originalFunction, sizeof(JmpCode), oldProtect, &oldProtect2);
}

}
