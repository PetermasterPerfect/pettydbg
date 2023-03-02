#include <windows.h>
#include <cstdio>

class Debugger
{
public:
	Debugger(const char*);
	Debugger(DWORD pid);
	
	VOID enterDebuggerLoop();

private:
	HANDLE hProcess;
	BOOL isAttached;
	HANDLE startup(const char*);
};