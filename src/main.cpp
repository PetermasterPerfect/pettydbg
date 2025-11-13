#include "commandsEvalListener.h"
#include "commandsLexer.h"
#include "dwarf.h"
#include "libdwarf.h"
#include <string>
#include <thread>
#include <locale>
#include <codecvt>

template <typename T>
void debuggerLoop(CommandsEvalListener<T> &commandsEval)
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

/*
VERY IMPORTANT
	The cmd parameter used to restart the debugged process MUST be quoted!
	It could be double, triple  quoted etc.
	(e.g """app.exe""" runs correctly)
	So if user gives as an argument cmd, we should make sure its quoted.
*/

int main(int argc, char** argv)
{
	DebugSetProcessKillOnExit(TRUE);
	if (argc < 2)
	{
		std::cerr << "USAGE dbg.exe <app_name.exe>/-p <PID>\n";
		return 3;
	}

	if (std::string(argv[1]) == "-p")
	{
		try
		{
			DWORD pid = std::stol(argv[2]);
			CommandsEvalListener<DWORD> commandsEval(pid);
			debuggerLoop<DWORD>(commandsEval);
		}
		catch (const std::invalid_argument& e)
		{
			std::cerr << "Invalid process id argument. Not a valid number.\n";
		}
		catch (const std::out_of_range& e)
		{
			std::cerr << "Invalid process id argument. Out of range.\n";
		}
	}
	else
	{
		/*const size_t cSize = strlen(argv[1]) + 1 + 2; // +2 is needed to adds quotes
		wchar_t* wc = new wchar_t[cSize];
		wc[0] = L'\"';
		mbstowcs(&wc[1], argv[1], cSize - 2);
		wc[cSize - 2] = L'\"';*/
		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
		std::string buf(argv[1]);
		std::wstring cmd = L"\"" + converter.from_bytes(buf) + L"\"";
		CommandsEvalListener<const wchar_t*> commandsEval(cmd.c_str());
		debuggerLoop<const wchar_t*>(commandsEval);
	}

	return 0;
}