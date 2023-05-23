#include <windows.h>
#include <cstdio>
#include <thread>
#include <sstream>
#include "commandline.h"

// TODO: decide whether isRunning = false; should be in breakCommand oor in exceptionEvent
// TODO: implement runCommand and continueCommand (they do the same at the moment) 

BOOL WINAPI registerSignals(DWORD);

class Debugger : public CommandLineInput
{
public:
	Debugger();
	Debugger(const char*);
	Debugger(DWORD pid);

	void enterDebuggerLoop();
	friend BOOL WINAPI registerSignals(DWORD);

private:
	DEBUG_EVENT debugEvent;
	PROCESS_INFORMATION procInfo;
	HANDLE hProcess;
	bool isAttached;
	bool isRunning;
	HANDLE startup(const char*);
	
	void continueCommand();
	void runCommand();
	void breakSignal();
	
	template<class... Args> void debuggerMessage(Args ...);
	template <typename T> std::string asHex(T);
	
	void handleCmd();
	void exceptionSwitchedCased();
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
