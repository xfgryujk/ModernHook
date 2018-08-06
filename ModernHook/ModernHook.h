#pragma once
#include <functional>
#include <memory>

#include <Windows.h>

namespace ModernHook
{

#ifdef MODERN_HOOK_EXPORTS
#define MODERN_HOOK_API __declspec(dllexport)
#else
#define MODERN_HOOK_API __declspec(dllimport)
#endif

// Support different calling conventions
#pragma region calling conventions macros
#define DEF_CDECL(FUNC, OPT1, OPT2, OPT3) \
	FUNC(__cdecl, OPT1, OPT2, OPT3)
#ifdef _M_CEE
#define DEF_CLRCALL(FUNC, OPT1, OPT2, OPT3) \
	FUNC(__clrcall, OPT1, OPT2, OPT3)
#else
#define DEF_CLRCALL(FUNC, OPT1, OPT2, OPT3)
#endif
#if defined(_M_IX86) && !defined(_M_CEE)
#define DEF_FASTCALL(FUNC, OPT1, OPT2, OPT3) \
	FUNC(__fastcall, OPT1, OPT2, OPT3)
#else
#define DEF_FASTCALL(FUNC, OPT1, OPT2, OPT3)
#endif
#ifdef _M_IX86
#define DEF_STDCALL(FUNC, OPT1, OPT2, OPT3) \
	FUNC(__stdcall, OPT1, OPT2, OPT3)
#define DEF_THISCALL(FUNC, OPT1, OPT2, OPT3) \
	FUNC(__thiscall, OPT1, OPT2, OPT3)
#else
#define DEF_STDCALL(FUNC, OPT1, OPT2, OPT3)
#define DEF_THISCALL(FUNC, OPT1, OPT2, OPT3)
#endif
#if ((defined(_M_IX86) && _M_IX86_FP >= 2) \
	|| defined(_M_X64)) && !defined(_M_CEE)
#define DEF_VECTORCALL(FUNC, OPT1, OPT2, OPT3) \
	FUNC(__vectorcall, OPT1, OPT2, OPT3)
#else
#define DEF_VECTORCALL(FUNC, OPT1, OPT2, OPT3)
#endif

#define DEF_NON_MEMBER(FUNC, CV_OPT, REF_OPT, NOEXCEPT_OPT) \
	DEF_CDECL(FUNC, CV_OPT, REF_OPT, NOEXCEPT_OPT) \
	DEF_CLRCALL(FUNC, CV_OPT, REF_OPT, NOEXCEPT_OPT) \
	DEF_FASTCALL(FUNC, CV_OPT, REF_OPT, NOEXCEPT_OPT) \
	DEF_STDCALL(FUNC, CV_OPT, REF_OPT, NOEXCEPT_OPT) \
	DEF_VECTORCALL(FUNC, CV_OPT, REF_OPT, NOEXCEPT_OPT)
#pragma endregion

namespace _internal
{

MODERN_HOOK_API LONG WINAPI DetourTransactionBegin(VOID);
MODERN_HOOK_API LONG WINAPI DetourTransactionCommit(VOID);
MODERN_HOOK_API LONG WINAPI DetourUpdateThread(_In_ HANDLE hThread);
MODERN_HOOK_API LONG WINAPI DetourAttach(_Inout_ PVOID *ppPointer, _In_ PVOID pDetour);
MODERN_HOOK_API LONG WINAPI DetourDetach(_Inout_ PVOID *ppPointer, _In_ PVOID pDetour);

struct VirtualAllocDeleter
{
	void operator()(void* pointer) { VirtualFree(pointer, 0, MEM_RELEASE); }
};
using VirtualAllocPtr = std::unique_ptr<void, VirtualAllocDeleter>;
MODERN_HOOK_API VirtualAllocPtr CreateHookFunctionEntry(void* templateFunction, SIZE_T templateFunctionSize,
	uintptr_t thisPlaceholder, void* thiz);
MODERN_HOOK_API void** FindImportAddress(HMODULE hookModule, LPCSTR moduleName, LPCSTR functionName);

}

#pragma region base
class MODERN_HOOK_API BaseHook
{
protected:
	bool isEnabled = false;

public:
	virtual ~BaseHook() = default;
	virtual bool IsEnabled() { return isEnabled; }
	virtual void Enable();
	virtual void Disable();
protected:
	virtual void SetIsEnabled(bool _isEnabled) { isEnabled = _isEnabled; }
	virtual void DoEnable() = 0;
	virtual void DoDisable() = 0;
};

template<class FunctionType>
class Hook;

#define DEF_HOOK(CV, X1, X2, X3) \
	template<class ResultType, class... ArgTypes>												   \
	class Hook<ResultType CV(ArgTypes...)> : public BaseHook									   \
	{																							   \
	public:																						   \
		using MyType = Hook<ResultType(ArgTypes...)>;											   \
		using FunctionType = ResultType CV(ArgTypes...);										   \
	protected:																					   \
		std::function<FunctionType> hookFunction;												   \
		const _internal::VirtualAllocPtr hookFunctionEntry = CreateHookFunctionEntry();			   \
																								   \
	public:																						   \
		Hook(std::function<FunctionType> _hookFunction) :										   \
			hookFunction(std::move(_hookFunction))												   \
		{																						   \
		}																						   \
		virtual ~Hook() = default;																   \
		virtual void SetHookFunction(std::function<FunctionType> _hookFunction)					   \
		{																						   \
			hookFunction = std::move(_hookFunction);											   \
		}																						   \
		virtual ResultType CallHookFunction(ArgTypes... args)									   \
		{																						   \
			return hookFunction(args...);														   \
		}																						   \
		virtual ResultType CallOriginalFunction(ArgTypes... args) = 0;							   \
																								   \
	protected:																					   \
		static constexpr uintptr_t THIS_PLACEHOLDER = (uintptr_t)0x8877665544332211;			   \
		static constexpr SIZE_T TEMPLATE_MAX_SIZE = 256;										   \
		static ResultType CV HookFunctionEntryTemplate(ArgTypes... args)						   \
		{																						   \
			/* Will be replaced by "this" */													   \
			auto thiz = reinterpret_cast<MyType*>(THIS_PLACEHOLDER);							   \
			return thiz->CallHookFunction(args...);												   \
		}																						   \
		_internal::VirtualAllocPtr CreateHookFunctionEntry()									   \
		{																						   \
			return _internal::CreateHookFunctionEntry(HookFunctionEntryTemplate,				   \
				TEMPLATE_MAX_SIZE, THIS_PLACEHOLDER, this);										   \
		}																						   \
	};
DEF_NON_MEMBER(DEF_HOOK, X1, X2, X3)
#undef DEF_HOOK
#pragma endregion


#pragma region address table hook
template<class FunctionType>
class AddressTableHook;

#define DEF_ADDRESS_TABLE_HOOK(CV, X1, X2, X3) \
	template<class ResultType, class... ArgTypes>															\
	class AddressTableHook<ResultType CV(ArgTypes...)> : public Hook<ResultType CV(ArgTypes...)>			\
	{																										\
	public:																									\
		using Base = Hook<ResultType CV(ArgTypes...)>; 														\
		using Base::FunctionType;																			\
	protected:																								\
		FunctionType** const pFunction = nullptr;															\
		FunctionType* const originalFunction = nullptr;														\
																											\
	public:																									\
		AddressTableHook(FunctionType** _pFunction, std::function<FunctionType> _hookFunction = nullptr) :	\
			Base(_hookFunction),																			\
			pFunction(_pFunction),																			\
			originalFunction(*pFunction)																	\
		{																									\
		}																									\
																											\
		AddressTableHook(const AddressTableHook&) = delete;													\
		virtual ~AddressTableHook() { Base::Disable(); } /* AddressTableHook::DoDisable() */				\
																											\
		virtual void DoEnable() { ModifyTable((FunctionType*)Base::hookFunctionEntry.get()); }				\
		virtual void DoDisable() { ModifyTable(originalFunction); }											\
		virtual ResultType CallOriginalFunction(ArgTypes... args)											\
		{																									\
			return originalFunction(args...);																\
		}																									\
																											\
	protected:																								\
		virtual void ModifyTable(FunctionType* newFunction)													\
		{																									\
			DWORD oldProtect = 0, oldProtect2 = 0;															\
			if (!VirtualProtect(pFunction, sizeof(*pFunction), PAGE_READWRITE, &oldProtect))				\
				oldProtect = 0;																				\
			*pFunction = newFunction;																		\
			VirtualProtect(pFunction, sizeof(*pFunction), oldProtect, &oldProtect2);						\
		}																									\
	};
DEF_NON_MEMBER(DEF_ADDRESS_TABLE_HOOK, X1, X2, X3)
#undef DEF_ADDRESS_TABLE_HOOK
#pragma endregion


#pragma region IAT hook
template<class FunctionType>
class IatHook;

#define DEF_IAT_HOOK(CV, X1, X2, X3) \
	template<class ResultType, class... ArgTypes>														   \
	class IatHook<ResultType CV(ArgTypes...)> : public AddressTableHook<ResultType CV(ArgTypes...)>		   \
	{																									   \
	public:																								   \
		using Base = AddressTableHook<ResultType CV(ArgTypes...)>;										   \
		using Base::FunctionType;																		   \
	public:																								   \
		IatHook(HMODULE hookModule, LPCSTR moduleName, LPCSTR functionName,								   \
				std::function<FunctionType> _hookFunction = nullptr) :									   \
			Base((FunctionType**)_internal::FindImportAddress(hookModule, moduleName, functionName),	   \
				_hookFunction)																			   \
		{																								   \
		}																								   \
																										   \
		IatHook(const IatHook&) = delete;																   \
		virtual ~IatHook() { Base::Disable(); } /* AddressTableHook::DoDisable() */						   \
	};
DEF_NON_MEMBER(DEF_IAT_HOOK, X1, X2, X3)
#undef DEF_IAT_HOOK
#pragma endregion


#pragma region inline hook
template<class FunctionType>
class InlineHook;

#define DEF_INLINE_HOOK(CV, X1, X2, X3) \
	template<class ResultType, class... ArgTypes>															\
	class InlineHook<ResultType CV(ArgTypes...)> : public Hook<ResultType CV(ArgTypes...)>					\
	{																										\
	public:																									\
		using Base = Hook<ResultType CV(ArgTypes...)>; 														\
		using Base::FunctionType;																			\
	protected:																								\
		FunctionType* originalFunction = nullptr;															\
																											\
	public:																									\
		InlineHook(FunctionType* _originalFunction, std::function<FunctionType> _hookFunction = nullptr) :	\
			Base(_hookFunction),																			\
			originalFunction(_originalFunction)																\
		{																									\
		}																									\
																											\
		InlineHook(const InlineHook&) = delete;																\
		virtual ~InlineHook() { Base::Disable(); } /* InlineHook::DoDisable()	*/							\
																											\
		virtual void DoEnable()																				\
		{																									\
			_internal::DetourTransactionBegin();															\
			_internal::DetourUpdateThread(GetCurrentThread());												\
			_internal::DetourAttach((void**)&originalFunction, Base::hookFunctionEntry.get());				\
			_internal::DetourTransactionCommit();															\
		}																									\
																											\
		virtual void DoDisable()																			\
		{																									\
			_internal::DetourTransactionBegin();															\
			_internal::DetourUpdateThread(GetCurrentThread());												\
			_internal::DetourDetach((void**)&originalFunction, Base::hookFunctionEntry.get());				\
			_internal::DetourTransactionCommit();															\
		}																									\
																											\
		virtual ResultType CallOriginalFunction(ArgTypes... args)											\
		{																									\
			return originalFunction(args...);																\
		}																									\
	};
DEF_NON_MEMBER(DEF_INLINE_HOOK, X1, X2, X3)
#undef DEF_INLINE_HOOK
#pragma endregion


// Clear defines
#ifndef MODERN_HOOK_DONT_CLEAR_DEFINES
#undef DEF_CDECL
#undef DEF_CLRCALL
#undef DEF_FASTCALL
#undef DEF_STDCALL
#undef DEF_THISCALL
#undef DEF_VECTORCALL

#undef DEF_NON_MEMBER
#endif

}
