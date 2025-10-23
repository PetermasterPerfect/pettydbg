#pragma once
#include "commandsBaseListener.h"
#include "debugger.h"

using namespace antlr4;
using namespace antlr4::tree;

extern DebuggerEngine* g_engine;

class LexerErrorListener : public BaseErrorListener
{
	void syntaxError(Recognizer* recognizer, Token* offendingSymbol, size_t line, size_t charPositionInLine,
		const std::string& msg, std::exception_ptr e)
	{
		throw std::runtime_error(msg);
	}

	void reportAmbiguity(Parser* recognizer, const dfa::DFA& dfa, size_t startIndex, size_t stopIndex, bool exact,
		const antlrcpp::BitSet& ambigAlts, atn::ATNConfigSet* configs)
	{
		throw std::runtime_error("Ambiguity");
	}
};



class CommandsEvalErrorListener : public BaseErrorListener
{
	void syntaxError(Recognizer* recognizer, Token* offendingSymbol, size_t line, size_t charPositionInLine,
		const std::string& msg, std::exception_ptr e)
	{

	}
};

class CommandsEvalErrorStrategy : public DefaultErrorStrategy
{
	void recover(Parser* recognizer, std::exception_ptr e)
	{
		throw std::runtime_error("recover");
	}

	Token* recoverInline(Parser* recognizer)
	{
		throw std::runtime_error("recoverInline");
	}

	void sync(Parser* recognizer)
	{
	}
};


template <typename T>
class CommandsEvalListener : public commandsBaseListener
{
public:
	CommandsEvalListener(T arg) : engine(arg) 
	{
		g_engine = &engine;
		SetConsoleCtrlHandler(registerSignals, TRUE);
	};
	//friend class CommandsEvalListener;
	DebuggerEngine engine;

private:
	std::optional<size_t> integerFromArgument(ParseTree*);
	std::optional<std::string> stringFromArgument(ParseTree*);
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
std::optional<size_t> CommandsEvalListener<T>::integerFromArgument(ParseTree *childTree)
{
	try
	{
		auto terminal = dynamic_cast<antlr4::tree::TerminalNode*>(childTree);

		if (terminal) 
		{
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
	}
	return std::nullopt;
}

template <typename T>
std::optional<std::string> CommandsEvalListener<T>::stringFromArgument(ParseTree* childTree)
{
	auto terminal = dynamic_cast<antlr4::tree::TerminalNode*>(childTree);

	if (terminal)
	{
		antlr4::Token* token = terminal->getSymbol();
		if (token->getType() == commandsParser::STRING)
			return token->getText();
	}
	return std::nullopt;
}

template <typename T>
void CommandsEvalListener<T>::enterCommand0Arg(commandsParser::Command0ArgContext* ctx)
{
	if (ctx->children.size() != 1)
		return;
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
	case commandsParser::LVAR:
		engine.showLocals();
		break;
	}
}

template <typename T>
void CommandsEvalListener<T>::enterCommand1Arg(commandsParser::Command1ArgContext* ctx)
{
	if (ctx->children.size() != 2)
		return;
	auto type = ctx->start->getType();
	auto val = integerFromArgument(ctx->children[1]);
	if (val)
	{
		switch (type)
		{
		case commandsParser::SYM:
			break;
		case commandsParser::STACK:
			engine.showStack(val.value());
		case commandsParser::DELBPOINT:
			engine.deleteBreakpoint(reinterpret_cast<PVOID>(val.value()));
		case commandsParser::BPOINT:
			engine.setBreakPoint(reinterpret_cast<PVOID>(val.value()));
			break;
		case commandsParser::LL:
			auto srcs = engine.findCurrentSource(val.value());
			if(srcs)
				std::cout << srcs.value();
			break;
		}
	}
	else if (type == commandsParser::PRINT)
	{
		auto name = stringFromArgument(ctx->children[1]);
		if (name)
			engine.printLocal(name.value());
	}

}

template <typename T>
void CommandsEvalListener<T>::enterCommand2Arg(commandsParser::Command2ArgContext* ctx)
{
	if (ctx->children.size() != 3)
		return;

	auto type = ctx->start->getType();
	size_t val[2] = {};

	for (size_t i = 1; i < ctx->children.size(); i++)
	{
		auto buf = integerFromArgument(ctx->children[i]);
		if (buf)
			val[i - 1] = buf.value();
		else
		{
			std::cerr << "Bad format of argument\n";
			return;
		}
	}
	switch (type)
	{
	case commandsParser::DISASSEMBLY:
		engine.disassembly(reinterpret_cast<PVOID>(val[0]), val[1]);
		break;
	}
}