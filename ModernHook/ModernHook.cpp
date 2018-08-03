#include "stdafx.h"
#include <string.h>

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


void** FindImportAddress(HANDLE hookModule, LPCSTR moduleName, LPCSTR functionName)
{
	auto hookModuleBase = (uintptr_t)hookModule;
	auto dosHeader = (PIMAGE_DOS_HEADER)hookModuleBase;
	auto ntHeader = PIMAGE_NT_HEADERS(hookModuleBase + dosHeader->e_lfanew);

	auto importTable = PIMAGE_IMPORT_DESCRIPTOR(hookModuleBase
		+ ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	for (; importTable->Characteristics != 0; importTable++)
	{
		if (_stricmp(LPCSTR(hookModuleBase + importTable->Name), moduleName) != 0)
			continue;

		auto info = PIMAGE_THUNK_DATA(hookModuleBase + importTable->OriginalFirstThunk);
		auto importAddress = (void**)(hookModuleBase + importTable->FirstThunk);
		for (; info->u1.AddressOfData != 0; info++, importAddress++)
		{
			if ((info->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0)
			{
				auto name = PIMAGE_IMPORT_BY_NAME(hookModuleBase + info->u1.AddressOfData);
				if (strcmp((LPCSTR)name->Name, functionName) == 0)
					return importAddress;
			}
		}
		return nullptr;
	}
	return nullptr;
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
