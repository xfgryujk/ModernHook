#include "stdafx.h"
#include "CppUnitTest.h"

#define MODERN_HOOK_DONT_CLEAR_DEFINES
#include "ModernHook.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

using namespace ModernHook;

namespace Test
{

TEST_CLASS(TestInlineHook)
{
private:
	#define DEF_ADD(CV, X1, X2, X3) \
		static __declspec(noinline) volatile int CV Add##CV(int a, int b)	\
		{																	\
			return a + b;													\
		}
	DEF_NON_MEMBER(DEF_ADD, X1, X2, X3)

	#define DEF_MY_ADD(CV, X1, X2, X3) \
		static int CV MyAdd##CV(int a, int b)		\
		{											\
			return a - b;							\
		}
	DEF_NON_MEMBER(DEF_MY_ADD, X1, X2, X3)

public:
	#define DEF_TEST_INLINE_HOOK_ENABLE(CV, X1, X2, X3) \
		TEST_METHOD(HookEnable##CV)																			\
		{																									\
			InlineHook<decltype(Add##CV)> hook(Add##CV, MyAdd##CV);											\
			hook.Enable();																					\
			Assert::AreEqual(0, Add##CV(1, 1), L"Enable failed");											\
		}
	DEF_NON_MEMBER(DEF_TEST_INLINE_HOOK_ENABLE, X1, X2, X3)

	#define DEF_TEST_INLINE_HOOK_DISABLE(CV, X1, X2, X3) \
		TEST_METHOD(HookDisable##CV)																		\
		{																									\
			InlineHook<decltype(Add##CV)> hook(Add##CV, MyAdd##CV);											\
			hook.Enable();																					\
			hook.Disable();																					\
			Assert::AreEqual(2, Add##CV(1, 1), L"Disable failed");											\
		}
	DEF_NON_MEMBER(DEF_TEST_INLINE_HOOK_DISABLE, X1, X2, X3)

	#define DEF_TEST_INLINE_LAMBDA(CV, X1, X2, X3) \
		TEST_METHOD(Lambda##CV)																				\
		{																									\
			int c = 0;																						\
			InlineHook<decltype(Add##CV)> hook(Add##CV, [&c](int a, int b) { return a + b + c; });			\
			hook.Enable();																					\
			c = 1;																							\
			Assert::AreEqual(3, Add##CV(1, 1), L"Lambda failed");											\
		}
	DEF_NON_MEMBER(DEF_TEST_INLINE_LAMBDA, X1, X2, X3)
		
	#define DEF_TEST_INLINE_RAII(CV, X1, X2, X3) \
		TEST_METHOD(Raii##CV)																				\
		{																									\
			{																								\
				InlineHook<decltype(Add##CV)> hook(Add##CV, MyAdd##CV);										\
				hook.Enable();																				\
			}																								\
			Assert::AreEqual(2, Add##CV(1, 1), L"Disable failed");											\
		}
	DEF_NON_MEMBER(DEF_TEST_INLINE_RAII, X1, X2, X3)

	#define DEF_TEST_INLINE_CALL_ORIG(CV, X1, X2, X3) \
		TEST_METHOD(CallOrig##CV)																			\
		{																									\
			InlineHook<decltype(Add##CV)> hook(Add##CV, MyAdd##CV);											\
			hook.Enable();																					\
			Assert::AreEqual(2, hook.CallOriginalFunction(1, 1), L"CallOrig failed");						\
		}
	DEF_NON_MEMBER(DEF_TEST_INLINE_CALL_ORIG, X1, X2, X3)
};

}
