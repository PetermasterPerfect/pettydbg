#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <cctype>

// Function replicated from LinuxDebugBackend for unit testing
static std::vector<std::string> splitCommandLine(const std::string& cmd)
{
	std::vector<std::string> args;
	std::string current;
	bool inQuotes = false;
	char quoteChar = 0;

	for (size_t i = 0; i < cmd.size(); ++i)
	{
		char c = cmd[i];
		if ((c == '"' || c == '\'') && !inQuotes)
		{
			inQuotes = true;
			quoteChar = c;
		}
		else if (inQuotes && c == quoteChar)
		{
			inQuotes = false;
		}
		else if (std::isspace(static_cast<unsigned char>(c)) && !inQuotes)
		{
			if (!current.empty())
			{
				args.push_back(current);
				current.clear();
			}
		}
		else
		{
			current.push_back(c);
		}
	}
	if (!current.empty())
		args.push_back(current);

	return args;
}

TEST(CommandLineParserTest, HandlesSimpleCommand)
{
	auto args = splitCommandLine("./test_program");
	ASSERT_EQ(args.size(), 1u);
	EXPECT_EQ(args[0], "./test_program");
}

TEST(CommandLineParserTest, HandlesArgumentsWithSpaces)
{
	auto args = splitCommandLine("./test_program -arg1 val1 -arg2 val2");
	ASSERT_EQ(args.size(), 5u);
	EXPECT_EQ(args[0], "./test_program");
	EXPECT_EQ(args[1], "-arg1");
	EXPECT_EQ(args[2], "val1");
	EXPECT_EQ(args[3], "-arg2");
	EXPECT_EQ(args[4], "val2");
}

TEST(CommandLineParserTest, HandlesDoubleQuotes)
{
	auto args = splitCommandLine("./test_program \"arg with spaces\" normal_arg");
	ASSERT_EQ(args.size(), 3u);
	EXPECT_EQ(args[0], "./test_program");
	EXPECT_EQ(args[1], "arg with spaces");
	EXPECT_EQ(args[2], "normal_arg");
}

TEST(CommandLineParserTest, HandlesSingleQuotes)
{
	auto args = splitCommandLine("./test_program 'single quoted string' second");
	ASSERT_EQ(args.size(), 3u);
	EXPECT_EQ(args[0], "./test_program");
	EXPECT_EQ(args[1], "single quoted string");
	EXPECT_EQ(args[2], "second");
}

TEST(CommandLineParserTest, HandlesEmptyOrWhitespace)
{
	auto args1 = splitCommandLine("");
	EXPECT_TRUE(args1.empty());

	auto args2 = splitCommandLine("    \t   ");
	EXPECT_TRUE(args2.empty());
}
