#include "commandsEvalListener.h"
#include "commandsLexer.h"
#include <string>
#include <thread>
#define TEST 1
#include "dwarf.h"
#include "libdwarf.h"

void commandPrompt()
{
	std::cout << ">>> ";
}

template <typename T>
void debuggerLoop(CommandsEvalListener<T> &commandsEval)
{
	std::string cmd;
	while (true)
	{
		if (!commandsEval.engine.isBusy())
		{
			commandPrompt();
			std::getline(std::cin, cmd);

			ANTLRInputStream input(cmd);
			commandsLexer lexer(&input);
			CommonTokenStream tokens(&lexer);
			commandsParser parser(&tokens);

			ParseTree* tree = parser.command();
			ParseTreeWalker walker;
			walker.walk(&commandsEval, tree);
		}
		commandsEval.engine.handleDebugEvent();
	}
}

/*
***
VERY IMPORTANT
	cmd parameter which is used later on to restart debugged process
	MUST BE QUOTED !!!
	It could be double, triple  quoted etc.
	(e.g """app.exe""" runs correctly) so
	if user gives as an argument cmd, it should make sure its quoted
***
*/


int main(int argc, char** argv)
{
	DebugSetProcessKillOnExit(TRUE);
#ifdef TEST
	wchar_t* cmd = new wchar_t[0x20];
	wcscpy(cmd, L"\"C:\\Users\\LENOVO\\test1.exe\"");

	CommandsEvalListener<wchar_t*> commandsEval(cmd);
	debuggerLoop<wchar_t*>(commandsEval);
#else

	if (argc < 2)
	{
		fprintf(stderr, "USAGE dbg.exe <app_name.exe>/-p <PID>\n");
		return 3;
	}

	if (std::string(argv[1]) == "-p")
		dbg = new Debugger(std::stoi(argv[2]));
	else
	{
		const size_t cSize = strlen(argv[1]) + 1 + 2; // +2 is needed to adds quotes
		wchar_t* wc = new wchar_t[cSize];
		wc[0] = L'\"';
		mbstowcs(&wc[1], argv[1], cSize - 2);
		wc[cSize - 2] = L'\"';
		dbg = new Debugger(wc);
	}
	dbg->enterDebuggerLoop();
#endif

}