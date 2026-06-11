#include "commandsEvalListener.h"
#include "commandsLexer.h"
#include "dwarf.h"
#include "libdwarf.h"
#include <string>
#include <thread>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

template <typename T>
void debuggerLoop(CommandsEvalListener<T>& commandsEval)
{
	std::string cmd;
	while (true)
	{
		commandsEval.engine.handleDebugEvent();
		if (!commandsEval.engine.isBusy())
		{
			do
			{
				std::cout << ">>> ";
			} while (!std::getline(std::cin, cmd));

			if (cmd.empty())
				continue;

			ANTLRInputStream input(cmd);
			commandsLexer lexer(&input);
			LexerErrorListener lexerErrListener;
			CommandsEvalErrorListener errListener;
			std::shared_ptr<CommandsEvalErrorStrategy> handler = std::make_shared<CommandsEvalErrorStrategy>();
			if (!handler)
				throw std::runtime_error("Memory allocation failed");
			lexer.removeErrorListeners();
			lexer.addErrorListener(&lexerErrListener);
			CommonTokenStream tokens(&lexer);
			commandsParser parser(&tokens);

			parser.setErrorHandler(handler);
			parser.removeErrorListeners();
			parser.addErrorListener(&errListener);

			try
			{
				ParseTree* tree = parser.command();
				ParseTreeWalker walker;
				walker.walk(&commandsEval, tree);
			}
			catch (const std::runtime_error& e)
			{
				std::cerr << "Bad command format\n";
			}
		}
	}
}

int main(int argc, char** argv)
{
#ifdef _WIN32
	DebugSetProcessKillOnExit(TRUE);
#endif
	if (argc < 2)
	{
		std::cerr << "USAGE pettydbg <app_name> / -p <PID>\n";
		return 3;
	}

	if (std::string(argv[1]) == "-p")
	{
		if (argc < 3)
		{
			std::cerr << "USAGE pettydbg -p <PID>\n";
			return 3;
		}
		try
		{
			uint64_t pid = std::stoull(argv[2]);
			CommandsEvalListener<uint64_t> commandsEval(pid);
			debuggerLoop<uint64_t>(commandsEval);
		}
		catch (const std::invalid_argument& e)
		{
			std::cerr << "Invalid process id argument. Not a valid number.\n";
		}
		catch (const std::out_of_range& e)
		{
			std::cerr << "Invalid process id argument. Out of range.\n";
		}
		catch (const std::exception& e)
		{
			std::cerr << "Cannot attach debugger: " << e.what() << "\n";
		}
	}
	else
	{
		std::string cmd = argv[1];
		for (int i = 2; i < argc; ++i)
		{
			cmd += " ";
			cmd += argv[i];
		}
		try
		{
			CommandsEvalListener<std::string> commandsEval(cmd);
			debuggerLoop<std::string>(commandsEval);
		}
		catch (const std::exception& e)
		{
			std::cerr << "Cannot continue debugging: " << e.what() << "\n";
		}
	}

	return 0;
}
