#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <sstream>
#include <map>
#include <vector>
#include <capstone/capstone.h>
#include "commandline.h"
#include "peb.h"
#include "unicodeStringEx.h"
#include "thread_info.h"

#define INT_1 0xCD01
#define INT_3 0xCC

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
	bool firstBreakpoint; // inspiration from https://github.com/x64dbg/TitanEngine
	bool steppingOut = false;
	std::map<DWORD, HANDLE> activeThreads;
	std::map<PVOID, BYTE> breakpoints;
	PVOID stepBreakpoint = nullptr;
	PVOID lastBreakpoint = nullptr;
	bool continueTrap = false;

	HANDLE startup(const wchar_t*);
	void continueIfAndRun(states);
	void continueExecution();
	void run();
	void breakSignal();
	void threadsInfo();
	void memoryMappingInfo();
	
	template<class... Args> void debuggerMessage(Args ...);
	template <typename T> std::string asHex(T);
	SIZE_T fromHex(std::string);
	std::string memStateAsString(DWORD);
	std::string memTypeAsString(DWORD);
	std::string argumentAsHex(std::string);
	
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
	PPEB loadPeb(SIZE_T* = nullptr);
	PRTL_USER_PROCESS_PARAMETERS loadProcessParameters();
	PPEB_LDR_DATA loadLoaderData();
	std::map<PVOID, std::string> sketchMemory();
	std::map<PVOID, std::string> sketchThreadMemory();
	std::map<PVOID, std::string> sketchModulesSections(PVOID, std::string);
	void cmdtest();
	void sketchMemoryTest();
	
	void dissassembly(PVOID, SIZE_T);
	void setBreakPoint(PVOID);
	void stepOver();
	void stepIn();
	void stepOut();
	void setSystemBreakpoint();
	void setTrapFlag();
	void unsetTrapFlag();
	void showStack(SIZE_T);
	void showGeneralPurposeRegisters();
	void breakpointsInfo();
	void deleteBreakpoint(PVOID);
	void replaceInt3(PVOID, BYTE*, SIZE_T);
	void attachRunningThreads();
};
