#pragma once

#include <array>

#include <Windows.h>

namespace ModernHook
{

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

// TODO Support other calling conventions
#define CV __stdcall

template<class FunctionType>
class Hook;

template<class ResultType, class... ArgTypes>
class Hook<ResultType CV(ArgTypes...)> : public BaseHook
{
public:
	using FunctionType = ResultType CV(ArgTypes...);

public:
	virtual ~Hook() = default;
	virtual ResultType CallOriginalFunction(ArgTypes... args) = 0;
};

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

template<class ResultType, class... ArgTypes>
class InlineHook<ResultType CV(ArgTypes...)> : public Hook<ResultType CV(ArgTypes...)>
{
private:
	FunctionType* const originalFunction = nullptr;
	FunctionType* const hookFunction = nullptr;
	const std::array<uint8_t, sizeof(JmpCode)> originalCode;

public:
	InlineHook(FunctionType* _originalFunction, FunctionType* _hookFunction, bool enable = true) :
		originalFunction(_originalFunction),
		hookFunction(_hookFunction)
	{
		memcpy((void*)&originalCode, originalFunction, sizeof(originalCode));

		if (enable)
			Enable();
	}

	virtual ~InlineHook() { Disable(); }

	virtual void DoEnable()
	{
		JmpCode code((uintptr_t)originalFunction, (uintptr_t)hookFunction);
		DWORD oldProtect, oldProtect2;
		VirtualProtect(originalFunction, sizeof(JmpCode), PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy(originalFunction, &code, sizeof(JmpCode));
		VirtualProtect(originalFunction, sizeof(JmpCode), oldProtect, &oldProtect2);
	}

	virtual void DoDisable()
	{
		DWORD oldProtect, oldProtect2;
		VirtualProtect(originalFunction, sizeof(JmpCode), PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy(originalFunction, &originalCode, sizeof(originalCode));
		VirtualProtect(originalFunction, sizeof(JmpCode), oldProtect, &oldProtect2);
	}

	virtual ResultType CallOriginalFunction(ArgTypes... args)
	{
		bool originalEnable = IsEnabled();
		Disable();
		ResultType result = originalFunction(args...);
		if (originalEnable)
			Enable();
		return result;
	}
};

}
