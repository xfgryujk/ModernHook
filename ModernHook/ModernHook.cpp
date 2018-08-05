#include <string.h>

#include "detours.h"
#include "ModernHook.h"

using namespace std;

namespace ModernHook
{

namespace _internal
{

MODERN_HOOK_API LONG WINAPI DetourTransactionBegin(VOID) { return ::DetourTransactionBegin(); }
MODERN_HOOK_API LONG WINAPI DetourTransactionCommit(VOID) { return ::DetourTransactionCommit(); }
MODERN_HOOK_API LONG WINAPI DetourUpdateThread(_In_ HANDLE hThread) { return ::DetourUpdateThread(hThread); }
MODERN_HOOK_API LONG WINAPI DetourAttach(_Inout_ PVOID *ppPointer, _In_ PVOID pDetour) { return ::DetourAttach(ppPointer, pDetour); }
MODERN_HOOK_API LONG WINAPI DetourDetach(_Inout_ PVOID *ppPointer, _In_ PVOID pDetour) { return ::DetourDetach(ppPointer, pDetour); }

MODERN_HOOK_API void** FindImportAddress(HMODULE hookModule, LPCSTR moduleName, LPCSTR functionName)
{
	struct Context
	{
		LPCSTR moduleName;
		LPCSTR functionName;
		bool isExpectedModule;
		void** importAddress;
	} ctx = { moduleName, functionName, false, nullptr };

	DetourEnumerateImportsEx(hookModule, &ctx,
		[](void* context, HMODULE module, LPCSTR moduleName)
		{
			auto ctx = (Context*)context;
			if (ctx->importAddress != nullptr)
				return FALSE;
			ctx->isExpectedModule = ctx->moduleName != NULL && moduleName != NULL &&
				_stricmp(ctx->moduleName, moduleName) == 0;
			return TRUE;
		},
		[](void* context, DWORD ordinal, LPCSTR functionName, void** importAddress)
		{
			auto ctx = (Context*)context;
			if (!ctx->isExpectedModule)
				return FALSE;
			if (ctx->functionName != NULL && functionName != NULL &&
				_stricmp(ctx->functionName, functionName) == 0)
			{
				ctx->importAddress = importAddress;
				return FALSE;
			}
			return TRUE;
		}
	);
	return ctx.importAddress;
}

}

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

}
