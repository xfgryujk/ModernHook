#include "stdafx.h"
#include "CppUnitTest.h"

#define MODERN_HOOK_DONT_CLEAR_DEFINES
#include "ModernHook.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

using namespace ModernHook;

namespace Test
{

#define DEF_ADD(CV, X1, X2, X3) \
	int CV Add##CV(int a, int b)		\
	{									\
		return a + b;					\
	}
DEF_NON_MEMBER(DEF_ADD, X1, X2, X3)

TEST_CLASS(TestInlineHook)
{
private:
	#define DEF_MY_ADD(CV, X1, X2, X3) \
		static int CV MyAdd##CV(int a, int b)		\
		{											\
			return a - b;							\
		}
	DEF_NON_MEMBER(DEF_MY_ADD, X1, X2, X3)

public:
	#define DEF_TEST_HOOK(CV, X1, X2, X3) \
		TEST_METHOD(Hook##CV)																\
		{																					\
			InlineHook<decltype(Add##CV)> messageBoxWHook(Add##CV, MyAdd##CV);				\
			Assert::AreEqual(0, Add##CV(1, 1));												\
		}
	DEF_NON_MEMBER(DEF_TEST_HOOK, X1, X2, X3)

	#define DEF_TEST_CALL_ORIG(CV, X1, X2, X3) \
		TEST_METHOD(CallOriginalFunction##CV)												\
		{																					\
			InlineHook<decltype(Add##CV)> messageBoxWHook(Add##CV, MyAdd##CV);				\
			Assert::AreEqual(2, messageBoxWHook.CallOriginalFunction(1, 1));				\
		}
	DEF_NON_MEMBER(DEF_TEST_CALL_ORIG, X1, X2, X3)
};

}
