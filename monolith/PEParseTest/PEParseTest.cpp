#include "pch.h"
#include "CppUnitTest.h"
#include "../PEParse/CommandLineParser.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace PEParseTest
{
	TEST_CLASS(PEParseTest)
	{
	public:

        TEST_METHOD(TestArgs)
        {

        }

        TEST_METHOD(TestMethod2)
        {
            Assert::AreEqual(1, 1);
        }
	};
}
