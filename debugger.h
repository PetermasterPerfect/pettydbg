#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <sstream>
#include <map>
#include "commandline.h"
#include "peb.h"
#include "unicodeStringEx.h"
#include "thread_info.h"

enum states{not_running, running, bpoint};

BOOL WINAPI registerSignals(DWORD);

class Debugger : public CommandLineInput
{
public:
	Debugger();
	Debugger(wchar_t *);
	Debugger(DWORD pid);

	void enterDebuggerLoop();
	friend BOOL WINAPI registerSignals(DWORD);

private:
	//TODO: clean up mess with process handle process id and PROCESS_INFORMATION structure
	DEBUG_EVENT debugEvent;
	PROCESS_INFORMATION procInfo;
	DWORD processId;
	HANDLE hProcess;
	states state;
	bool isAttached;
	bool isRunning;
	bool firstBreakpoint; // inspiration from TitanEngine
	std::map<DWORD, HANDLE> activeThreads;

	HANDLE startup(const wchar_t*);
	
	void continueCommand();
	void runCommand();
	void breakSignal();
	void enumerateThreadsCommand();
	void enumerateMemoryPagesCommand();
	
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
	NtQueryInformationThread getNtQueryInformationThread();
	PPEB loadPeb();
	PRTL_USER_PROCESS_PARAMETERS loadProcessParameters();
	PPEB_LDR_DATA loadLoaderData();
	std::map<PVOID, std::string> sketchMemory();
	std::map<PVOID, std::string> sketchThreadMemory();
	void cmdtest();
	void sketchMemoryTest();
	HANDLE dupHandle(HANDLE);
};
