#pragma once
#include "commandsBaseListener.h"
#include "debugger.h"

using namespace antlr4;
using namespace antlr4::tree;

extern DebuggerEngine* g_engine;

template <typename T>
class CommandsEvalListener : public commandsBaseListener
{
public:
	CommandsEvalListener(T arg) : engine(arg) 
	{
		g_engine = &engine;
		SetConsoleCtrlHandler(registerSignals, TRUE);
	};
	friend class CommandsEvalListener;
	DebuggerEngine engine;

private:
	size_t valueFromArgument(ParseTree*);
	size_t fromHex(std::string);
	void enterCommand0Arg(commandsParser::Command0ArgContext* /*ctx*/) override;
	void enterCommand1Arg(commandsParser::Command1ArgContext* /*ctx*/) override;
	void enterCommand2Arg(commandsParser::Command2ArgContext* /*ctx*/) override;
	
};
template <typename T>
size_t CommandsEvalListener<T>::fromHex(std::string str)
{
	size_t x;
	std::stringstream ss;
	ss << std::hex << str;
	ss >> x;
	return x;
}

template <typename T>
size_t CommandsEvalListener<T>::valueFromArgument(ParseTree *childTree)
{
	try
	{
		auto* terminal = dynamic_cast<antlr4::tree::TerminalNode*>(childTree);

		if (terminal) {
			antlr4::Token* token = terminal->getSymbol();
			if (token->getType() == commandsParser::INT)
				return std::stol(token->getText());
			else if (token->getType() == commandsParser::HEXINT)
				return fromHex(token->getText());
		}
	}
	catch (const std::out_of_range& ex)
	{
		std::cerr << "Given number argument out of range\n";
		throw ex;
	}
}

template <typename T>
void CommandsEvalListener<T>::enterCommand0Arg(commandsParser::Command0ArgContext* ctx)
{

	//ANTLRInputStream s("dsads");
	auto type = ctx->start->getType();
	switch (type)
	{
	case commandsParser::CONTINUE:
		engine.continueExecution();
		break;
	case commandsParser::RESTART:
		engine.restart();
		break;
	case commandsParser::THREADINFO:
		engine.threadsInfo();
		break;
	case commandsParser::MEMINFO:
		engine.memoryMappingInfo();
		break;
	case commandsParser::NEXT:
		engine.stepOver();
		break;
	case commandsParser::STEPINTO:
		engine.stepIn();
		break;
	//case commandsLexer::FINISH:
	//	engine.finish();
	case commandsParser::REGISTERS:
		engine.showGeneralPurposeRegisters();
	case commandsParser::BPOINTINFO:
		engine.breakpointsInfo();
		break;
	}
}

template <typename T>
void CommandsEvalListener<T>::enterCommand1Arg(commandsParser::Command1ArgContext* ctx)
{
	auto type = ctx->start->getType();
	size_t val = valueFromArgument(ctx->children[1]);
	switch (type)
	{
	case commandsParser::STACK:
		engine.showStack(val);
	case commandsParser::DELBPOINT:
		engine.deleteBreakpoint(reinterpret_cast<PVOID>(val));
	case commandsParser::BPOINT:
		engine.setBreakPoint(reinterpret_cast<PVOID>(val));
		break;
	}

}

template <typename T>
void CommandsEvalListener<T>::enterCommand2Arg(commandsParser::Command2ArgContext* ctx)
{
	auto type = ctx->start->getType();
	size_t val[2] = {};

	for (size_t i = 1; i < ctx->children.size(); i++)
		val[i - 1] = valueFromArgument(ctx->children[i]);

	switch (type)
	{
	case commandsParser::DISASSEMBLY:
		engine.dissassembly(reinterpret_cast<PVOID>(val[0]), val[1]);
		break;
	}
}