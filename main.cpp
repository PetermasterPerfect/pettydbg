#include "debugger.h"


// x86_64-w64-mingw32-g++ main.cpp debugger.cpp -o dbg.exe
int main()
{
	Debugger dbg("test.exe");
	dbg.enterDebuggerLoop();
}