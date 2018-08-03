#include "stdafx.h"
#include "CppUnitTest.h"

#include <string>

#include "ModernHook.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

using namespace std;

using namespace ModernHook;

namespace Test
{
	int __stdcall Add(int a, int b)
	{
		return a + b;
	}

	TEST_CLASS(TestInlineHook)
	{
	private:
		static int __stdcall MyAdd(int a, int b)
		{
			return a - b;
		}

	public:
		TEST_METHOD(Hook)
		{
			InlineHook<decltype(Add)> messageBoxWHook(Add, MyAdd);
			Assert::AreEqual(0, Add(1, 1));
		}

		TEST_METHOD(CallOriginalFunction)
		{
			InlineHook<decltype(Add)> messageBoxWHook(Add, MyAdd);
			Assert::AreEqual(2, messageBoxWHook.CallOriginalFunction(1, 1));
		}
	};
}
