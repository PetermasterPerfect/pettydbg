#include <windows.h>
#include <cstdio>

class Debugger
{
public:
	Debugger(const char*);
	Debugger(DWORD pid);
	
	void enterDebuggerLoop();

private:
	HANDLE hProcess;
	bool isAttached;
	HANDLE startup(const char*);
};