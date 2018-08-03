#include "stdafx.h"
#include "CppUnitTest.h"

#include <string>

#include "ModernHook.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

using namespace std;

using namespace ModernHook;

namespace Test
{
	TEST_CLASS(TestInlineHook)
	{
	private:
		static int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
		{
			return -1;
		}

	public:
		TEST_METHOD(Hook)
		{
			InlineHook messageBoxWHook(MessageBoxW, MyMessageBoxW);
			Assert::AreEqual(-1, MessageBoxW(NULL, L"", L"", MB_OK));
		}
	};
}
