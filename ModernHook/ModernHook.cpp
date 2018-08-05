#include <string.h>
#include <string_view>

#include "detours.h"
#include "ModernHook.h"

using namespace std;

namespace
{

//////////////////////////////////////////////// Helper functions copied from detours
//
constexpr ULONG DETOUR_REGION_SIZE = 0x10000;
const PVOID SYSTEM_REGION_LOWER_BOUND = (PVOID)(ULONG_PTR)0x70000000;
const PVOID SYSTEM_REGION_UPPER_BOUND = (PVOID)(ULONG_PTR)0x80000000;

inline ULONG_PTR detour_2gb_below(ULONG_PTR address)
{
    return (address > (ULONG_PTR)0x7ff80000) ? address - 0x7ff80000 : 0x80000;
}

inline ULONG_PTR detour_2gb_above(ULONG_PTR address)
{
#if defined(DETOURS_64BIT)
    return (address < (ULONG_PTR)0xffffffff80000000) ? address + 0x7ff80000 : (ULONG_PTR)0xfffffffffff80000;
#else
    return (address < (ULONG_PTR)0x80000000) ? address + 0x7ff80000 : (ULONG_PTR)0xfff80000;
#endif
}

inline void detour_find_jmp_bounds(PBYTE pbCode,
                                   ULONG_PTR *ppLower,
                                   ULONG_PTR *ppUpper)
{
    // We have to place trampolines within +/- 2GB of code.
    ULONG_PTR lo = detour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = detour_2gb_above((ULONG_PTR)pbCode);

    // And, within +/- 2GB of relative jmp targets.
    if (pbCode[0] == 0xe9) {   // jmp +imm32
        PBYTE pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];

        if (pbNew < pbCode) {
            hi = detour_2gb_above((ULONG_PTR)pbNew);
        }
        else {
            lo = detour_2gb_below((ULONG_PTR)pbNew);
        }
    }

    *ppLower = lo;
    *ppUpper = hi;
}

PBYTE detour_alloc_round_down_to_region(PBYTE pbTry)
{
	// WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
	ULONG_PTR extra = ((ULONG_PTR)pbTry) & (DETOUR_REGION_SIZE - 1);
	if (extra != 0) {
		pbTry -= extra;
	}
	return pbTry;
}

PBYTE detour_alloc_round_up_to_region(PBYTE pbTry)
{
	// WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
	ULONG_PTR extra = ((ULONG_PTR)pbTry) & (DETOUR_REGION_SIZE - 1);
	if (extra != 0) {
		ULONG_PTR adjust = DETOUR_REGION_SIZE - extra;
		pbTry += adjust;
	}
	return pbTry;
}

// Starting at pbLo, try to allocate a memory region, continue until pbHi.

PVOID detour_alloc_region_from_lo(PBYTE pbLo, PBYTE pbHi)
{
	PBYTE pbTry = detour_alloc_round_up_to_region(pbLo);

	for (; pbTry < pbHi;) {
		MEMORY_BASIC_INFORMATION mbi;

		if (pbTry >= SYSTEM_REGION_LOWER_BOUND && pbTry <= SYSTEM_REGION_UPPER_BOUND) {
			// Skip region reserved for system DLLs, but preserve address space entropy.
			pbTry += 0x08000000;
			continue;
		}

		ZeroMemory(&mbi, sizeof(mbi));
		if (!VirtualQuery(pbTry, &mbi, sizeof(mbi))) {
			break;
		}

		if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE) {

			PVOID pv = VirtualAlloc(pbTry,
				DETOUR_REGION_SIZE,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE);
			if (pv != NULL) {
				return pv;
			}
			pbTry += DETOUR_REGION_SIZE;
		}
		else {
			pbTry = detour_alloc_round_up_to_region((PBYTE)mbi.BaseAddress + mbi.RegionSize);
		}
	}
	return NULL;
}

// Starting at pbHi, try to allocate a memory region, continue until pbLo.

PVOID detour_alloc_region_from_hi(PBYTE pbLo, PBYTE pbHi)
{
	PBYTE pbTry = detour_alloc_round_down_to_region(pbHi - DETOUR_REGION_SIZE);

	for (; pbTry > pbLo;) {
		MEMORY_BASIC_INFORMATION mbi;

		if (pbTry >= SYSTEM_REGION_LOWER_BOUND && pbTry <= SYSTEM_REGION_UPPER_BOUND) {
			// Skip region reserved for system DLLs, but preserve address space entropy.
			pbTry -= 0x08000000;
			continue;
		}

		ZeroMemory(&mbi, sizeof(mbi));
		if (!VirtualQuery(pbTry, &mbi, sizeof(mbi))) {
			break;
		}

		if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE) {

			PVOID pv = VirtualAlloc(pbTry,
				DETOUR_REGION_SIZE,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE);
			if (pv != NULL) {
				return pv;
			}
			pbTry -= DETOUR_REGION_SIZE;
		}
		else {
			pbTry = detour_alloc_round_down_to_region((PBYTE)mbi.AllocationBase
				- DETOUR_REGION_SIZE);
		}
	}
	return NULL;
}

void* AllocHookFunctionEntry(void* _templateFunction)
{
	auto templateFunction = (PBYTE)_templateFunction;
	ULONG_PTR pLo;
	ULONG_PTR pHi;
	detour_find_jmp_bounds((PBYTE)templateFunction, &pLo, &pHi);
	void* result = detour_alloc_region_from_hi((PBYTE)pLo, templateFunction);
	if (result == NULL) {
		result = detour_alloc_region_from_lo(templateFunction, (PBYTE)pHi);
	}
	return result;
}

}

namespace ModernHook
{

namespace _internal
{

MODERN_HOOK_API LONG WINAPI DetourTransactionBegin(VOID) { return ::DetourTransactionBegin(); }
MODERN_HOOK_API LONG WINAPI DetourTransactionCommit(VOID) { return ::DetourTransactionCommit(); }
MODERN_HOOK_API LONG WINAPI DetourUpdateThread(_In_ HANDLE hThread) { return ::DetourUpdateThread(hThread); }
MODERN_HOOK_API LONG WINAPI DetourAttach(_Inout_ PVOID *ppPointer, _In_ PVOID pDetour) { return ::DetourAttach(ppPointer, pDetour); }
MODERN_HOOK_API LONG WINAPI DetourDetach(_Inout_ PVOID *ppPointer, _In_ PVOID pDetour) { return ::DetourDetach(ppPointer, pDetour); }

MODERN_HOOK_API VirtualAllocPtr CreateHookFunctionEntry(void* _templateFunction, SIZE_T templateFunctionSize,
	uintptr_t thisPlaceholder, void* thiz)
{
	auto templateFunction = (uint8_t*)_templateFunction;
	if (*templateFunction == 0xE9) // jmp
		templateFunction += 5 + *(int32_t*)(templateFunction + 1);
	templateFunction = (uint8_t*)DetourCodeFromPointer(templateFunction, NULL);

	auto result = AllocHookFunctionEntry(templateFunction);
	
	// Copy templateFunction to result
	auto templateFunctionEnd = PVOID(templateFunction + templateFunctionSize);
	auto src = templateFunction;
	auto dst = (uint8_t*)result;
	LONG extra = 0;
	while (src < templateFunctionEnd)
	{
		auto nextSrc = (uint8_t*)DetourCopyInstruction(dst, &templateFunctionEnd, src, NULL, &extra);
		dst += (nextSrc - src) + extra;
		src = nextSrc;
	}

	// Replace all placeholders with "this"
	string_view entryCode((char*)result, templateFunctionSize);
	size_t startPos = 0;
	while (true)
	{
		size_t placeholderPos = entryCode.find((char*)&thisPlaceholder, startPos, sizeof(thisPlaceholder));
		if (placeholderPos == string_view::npos)
			break;
		*(void**)((uintptr_t)result + placeholderPos) = thiz;
		startPos = placeholderPos;
	}

	DWORD oldProtect;
	VirtualProtect(result, templateFunctionSize, PAGE_EXECUTE_READ, &oldProtect);
	return VirtualAllocPtr(result);
}

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
