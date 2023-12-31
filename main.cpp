// x86_64-w64-mingw32-g++ main.cpp debugger.cpp commandline.cpp splitstring.cpp -o dbg.exe -static -std=c++17
#include <fstream>
#include "main.h"
//#define TEST 1

Debugger *dbg;

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
#ifdef TEST
	wchar_t *cmd = new wchar_t[0x20];
	wcscpy(cmd, L"\"test.exe\"");

	dbg = new Debugger(cmd);
	dbg->enterDebuggerLoop();
#else

	if(argc < 2)
	{
		fprintf(stderr, "USAGE dbg.exe <app_name.exe>/-p <PID>\n");
		return 3;
	}

	if(std::string(argv[1]) == "-p")
		dbg = new Debugger(std::stoi(argv[2]));
	else
	{
		const size_t cSize = strlen(argv[1])+1+2; // +2 is needed to adds quotes
		wchar_t* wc = new wchar_t[cSize];
		wc[0] = L'\"';
		mbstowcs (&wc[1], argv[1], cSize-2);
		wc[cSize-2] = L'\"';
		printf("wc %ls\n", wc);
		dbg = new Debugger(wc);
	}
	dbg->enterDebuggerLoop();
#endif

}
