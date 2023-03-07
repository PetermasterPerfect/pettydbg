#include <windows.h>
#include <cstdio>
#include "commandline.h"

// TODO: decide whether isRunning = false; should be in breakCommand oor in exceptionEvent
// TODO: implement runCommand and continueCommand (they are the same now) 

class Debugger : public CommandLineInput
{
public:
	Debugger();
	Debugger(const char*);
	Debugger(DWORD pid);

	void enterDebuggerLoop();

private:
	DEBUG_EVENT debugEvent;
	HANDLE hProcess;
	bool isAttached;
	bool isRunning;
	HANDLE startup(const char*);
	
	void continueCommand();
	void runCommand();
	void breakCommand();
	
	void handleCmd();
	void changeStatus(std::string);
	
	void exceptionEvent();
	void createThreadEvent();
	void createProcessEvent();
	void exitThreadEvent();
	void exitProcessEvent();
	void loadDllEvent();
	void unloadDllEvent();
	void outputDebugStringEvent();
	void ripEvent();
};
