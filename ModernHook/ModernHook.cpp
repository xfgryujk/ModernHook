#include "stdafx.h"

#include "ModernHook.h"

namespace ModernHook
{

void BaseHook::Enable()
{
	if (IsEnabled())
		return;
	DoEnable();
	SetIsEnabled(true);
}

void BaseHook::Disable()
{
	if (!IsEnabled())
		return;
	DoDisable();
	SetIsEnabled(false);
}

#ifndef _WIN64 // x86
JmpCode::JmpCode(uintptr_t srcAddr, uintptr_t dstAddr)
{
	SetAddress(srcAddr, dstAddr);
}

void JmpCode::SetAddress(uintptr_t srcAddr, uintptr_t dstAddr)
{
	relativeAddress = dstAddr - srcAddr - sizeof(JmpCode);
}
#else // x64
JmpCode::JmpCode(uintptr_t srcAddr, uintptr_t dstAddr)
{
	SetAddress(srcAddr, dstAddr);
}

void JmpCode::SetAddress(uintptr_t srcAddr, uintptr_t dstAddr)
{
	address = dstAddr;
}
#endif

}
