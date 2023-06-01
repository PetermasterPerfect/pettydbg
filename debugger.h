#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <sstream>
#include "commandline.h"
#include "peb.h"

// STATUS_SUCESS is equal 0x0
#define NT_SUCCESS(s) (s == 0 ? 1 : 0)

// TODO: decide whether isRunning = false; should be in breakCommand oor in exceptionEvent
// TODO: implement runCommand and continueCommand (they do the same at the moment) 

enum states{not_running, running, bpoint};

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
	DWORD processId;
	HANDLE hProcess;
	states state;
	bool isAttached;
	bool isRunning;
	bool firstBreakpoint; // inspiration from TitanEngine
	HANDLE startup(const char*);
	
	void continueCommand();
	void runCommand();
	void breakSignal();
	void enumerateThreadsCommand();
	
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
	
	NtQueryInformationProcess getNtQueryInformationProcess();
	PPEB loadPeb();
	void pebtest();
};
