# ModernHook
Implements Windows API hooks in modern C++

## Usage
### Basic hooking
```C++
#include "ModernHook.h"

int WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
ModernHook::InlineHook<decltype(MessageBoxA)> messageBoxAHook(MessageBoxA, MyMessageBoxA);

int main()
{
	messageBoxAHook.Enable();
	MessageBoxA(NULL, "test", "test", MB_OK);
	messageBoxAHook.Disable();
	MessageBoxA(NULL, "test", "test", MB_OK);
	return 0;
}

int WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	return messageBoxAHook.CallOriginalFunction(hWnd, "Hooked!", lpCaption, uType);
}
```

### Using lambda
> You can use `std::function` as hook function

```C++
int main()
{
	ModernHook::InlineHook<decltype(MessageBoxA)> messageBoxAHook(MessageBoxA);
	LPCSTR message = "Hooked!";
	messageBoxAHook.SetHookFunction([&](HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
	{
		return messageBoxAHook.CallOriginalFunction(hWnd, message, lpCaption, uType);
	});
	messageBoxAHook.Enable();
	MessageBoxA(NULL, "test", "test", MB_OK);
	message = "Another message";
	MessageBoxA(NULL, "test", "test", MB_OK);
	return 0;
}
```

### IAT hook
```C++
int main()
{
	ModernHook::IatHook<decltype(MessageBoxA)> messageBoxAHook(GetModuleHandle(NULL), "user32.dll", "MessageBoxA");
	messageBoxAHook.SetHookFunction([&](HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
	{
		return messageBoxAHook.CallOriginalFunction(hWnd, "Hooked!", lpCaption, uType);
	});
	messageBoxAHook.Enable();
	MessageBoxA(NULL, "test", "test", MB_OK);
	return 0;
}
```
