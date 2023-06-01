#include <fstream>
#include "main.h"

Debugger *dbg;
// x86_64-w64-mingw32-g++ main.cpp debugger.cpp commandline.cpp splitstring.cpp -o dbg.exe -static -std=c++17
int main(int argc, char** argv)
{
	wchar_t *cmd = new wchar_t[0x20];
	wcscpy (cmd, L"test.exe");
	dbg = new Debugger(cmd);
	dbg->enterDebuggerLoop();
/*	
	if(argc < 2)
	{
		fprintf(stderr, "USAGE dbg.exe <app_name.exe>/<-p PID>\n");
		return 3;
	}

	CommandLineInput cmdIn;
	if(std::string(argv[1]) == "-p")
	{
		Debugger dbg(std::stoi(argv[1]));
		if(hProcess == NULL)
			return 5;
	}
	else
	{
		Debugger dbg(argv[1]);
		if(hProcess == NULL)
			return 5;
	}
	dbg.enterDebuggerLoop();*/
}
