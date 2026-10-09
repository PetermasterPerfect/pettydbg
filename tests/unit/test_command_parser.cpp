#include <gtest/gtest.h>
#include "antlr4-runtime.h"
#include "commandsLexer.h"
#include "commandsParser.h"

using namespace antlr4;

TEST(CommandParserTest, ParsesContinueCommand)
{
	ANTLRInputStream input("c");
	commandsLexer lexer(&input);
	CommonTokenStream tokens(&lexer);
	commandsParser parser(&tokens);

	auto* tree = parser.command();
	ASSERT_NE(tree, nullptr);
	EXPECT_EQ(parser.getNumberOfSyntaxErrors(), 0u);
}

TEST(CommandParserTest, ParsesBreakpointCommand)
{
	ANTLRInputStream input("bp 0x401122");
	commandsLexer lexer(&input);
	CommonTokenStream tokens(&lexer);
	commandsParser parser(&tokens);

	auto* tree = parser.command();
	ASSERT_NE(tree, nullptr);
	EXPECT_EQ(parser.getNumberOfSyntaxErrors(), 0u);
}

TEST(CommandParserTest, ParsesDisassemblyCommand)
{
	ANTLRInputStream input("dis 0x401000 64");
	commandsLexer lexer(&input);
	CommonTokenStream tokens(&lexer);
	commandsParser parser(&tokens);

	auto* tree = parser.command();
	ASSERT_NE(tree, nullptr);
	EXPECT_EQ(parser.getNumberOfSyntaxErrors(), 0u);
}

TEST(CommandParserTest, ParsesPrintVariableCommand)
{
	ANTLRInputStream input("p $myVar123");
	commandsLexer lexer(&input);
	CommonTokenStream tokens(&lexer);
	commandsParser parser(&tokens);

	auto* tree = parser.command();
	ASSERT_NE(tree, nullptr);
	EXPECT_EQ(parser.getNumberOfSyntaxErrors(), 0u);
}

TEST(CommandParserTest, FailsOnInvalidCommand)
{
	ANTLRInputStream input("invalid_cmd_xyz 123");
	commandsLexer lexer(&input);
	CommonTokenStream tokens(&lexer);
	commandsParser parser(&tokens);

	auto* tree = parser.command();
	EXPECT_GT(parser.getNumberOfSyntaxErrors(), 0u);
}
