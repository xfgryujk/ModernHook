#pragma once

#include <array>

#include <Windows.h>

namespace ModernHook
{

class Hook
{
protected:
	bool isEnabled = false;

public:
	virtual ~Hook() = default;
	virtual bool IsEnabled() { return isEnabled; }
	virtual void Enable();
	virtual void Disable();
protected:
	virtual void SetIsEnabled(bool _isEnabled) { isEnabled = _isEnabled; }
	virtual void DoEnable() = 0;
	virtual void DoDisable() = 0;
};

class InlineHook : public Hook
{
private:
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

private:
	void* const originalFunction = nullptr;
	void* const hookFunction = nullptr;
	std::array<uint8_t, sizeof(JmpCode)> originalCode;

public:
	InlineHook(void* originalFunction, void* hookFunction, bool enable = true);
	virtual ~InlineHook() { Disable(); }
	virtual void DoEnable();
	virtual void DoDisable();
};

}
