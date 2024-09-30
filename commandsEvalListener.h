#pragma once
#include "commandsBaseListener.h"
#include "debugger.h"

template <typename T>
class CommandsEvalListener : public commandsBaseListener
{
	DebuggerEngine dbg;
	CommandsEvalListener(T arg) : dbg(arg) {};
	void enterCommand0arg(commandsParser::Command0argContext* /*ctx*/) override;
	void enterCommand1arg(commandsParser::Command1argContext* /*ctx*/) override;
	void enterCommand2arg(commandsParser::Command2argContext* /*ctx*/) override;
};
