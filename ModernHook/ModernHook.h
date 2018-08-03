#pragma once

#include <array>

#include <Windows.h>

namespace ModernHook
{

// Support calling conventions

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


class BaseHook
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
	template<class ResultType, class... ArgTypes>						\
	class Hook<ResultType CV(ArgTypes...)> : public BaseHook			\
	{																	\
	public:																\
		using FunctionType = ResultType CV(ArgTypes...);				\
																		\
	public:																\
		virtual ~Hook() = default;										\
		virtual ResultType CallOriginalFunction(ArgTypes... args) = 0;	\
	};
DEF_NON_MEMBER(DEF_HOOK, X1, X2, X3)
#undef DEF_HOOK


#pragma pack(push)
#pragma pack(1)
class JmpCode
{
private:
#ifndef _WIN64 // x86
	// jmp XXXXXXXX
	const uint8_t code = 0xE9;
	uintptr_t relativeAddress = 0;
#else // x64
	// jmp [RIP]
	const std::array<uint8_t, 6> code = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
	uintptr_t address = 0;
#endif

public:
	JmpCode() = default;
	JmpCode(uintptr_t srcAddr, uintptr_t dstAddr);
	void SetAddress(uintptr_t srcAddr, uintptr_t dstAddr);
};
#pragma pack(pop)

template<class FunctionType>
class InlineHook;

#define DEF_INLINE_HOOK(CV, X1, X2, X3) \
	template<class ResultType, class... ArgTypes>														\
	class InlineHook<ResultType CV(ArgTypes...)> : public Hook<ResultType CV(ArgTypes...)>				\
	{																									\
	private:																							\
		FunctionType* const originalFunction = nullptr;													\
		FunctionType* const hookFunction = nullptr;														\
		const std::array<uint8_t, sizeof(JmpCode)> originalCode;										\
																										\
	public:																								\
		InlineHook(FunctionType* _originalFunction, FunctionType* _hookFunction, bool enable = true) :	\
			originalFunction(_originalFunction),														\
			hookFunction(_hookFunction)																	\
		{																								\
			memcpy((void*)&originalCode, originalFunction, sizeof(originalCode));						\
																										\
			if (enable)																					\
				Enable();																				\
		}																								\
																										\
		virtual ~InlineHook() { Disable(); }															\
																										\
		virtual void DoEnable()																			\
		{																								\
			JmpCode code((uintptr_t)originalFunction, (uintptr_t)hookFunction);							\
			DWORD oldProtect, oldProtect2;																\
			VirtualProtect(originalFunction, sizeof(JmpCode), PAGE_EXECUTE_READWRITE, &oldProtect);		\
			memcpy(originalFunction, &code, sizeof(JmpCode));											\
			VirtualProtect(originalFunction, sizeof(JmpCode), oldProtect, &oldProtect2);				\
		}																								\
																										\
		virtual void DoDisable()																		\
		{																								\
			DWORD oldProtect, oldProtect2;																\
			VirtualProtect(originalFunction, sizeof(JmpCode), PAGE_EXECUTE_READWRITE, &oldProtect);		\
			memcpy(originalFunction, &originalCode, sizeof(originalCode));								\
			VirtualProtect(originalFunction, sizeof(JmpCode), oldProtect, &oldProtect2);				\
		}																								\
																										\
		virtual ResultType CallOriginalFunction(ArgTypes... args)										\
		{																								\
			bool originalEnable = IsEnabled();															\
			Disable();																					\
			ResultType result = originalFunction(args...);												\
			if (originalEnable)																			\
				Enable();																				\
			return result;																				\
		}																								\
	};
DEF_NON_MEMBER(DEF_INLINE_HOOK, X1, X2, X3)
#undef DEF_INLINE_HOOK

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
