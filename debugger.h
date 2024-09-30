#pragma once
#include "commandline.h"
#include <windows.h>
#include <tlhelp32.h>
#include <sstream>
#include <map>
#include <vector>
#include <memory>
#include <stdexcept>
#include <iomanip>
#include "peb.h"
#include "unicodeStringEx.h"
#include "thread_info.h"
#include <inttypes.h>
#include <Zydis/Zydis.h>

#define INT_1 0xCD01
#define INT_3 0xCC

enum states{not_running, running, breakpoint};

struct SmartHandleDeleter
{
	BOOL operator()(HANDLE h) const {
		CloseHandle(h);
	}
};

using SmartHandle = std::unique_ptr<void, SmartHandleDeleter>;

class DebuggerEngine : public CommandLineInput
{
public:
	DebuggerEngine();
	DebuggerEngine(wchar_t *);
	DebuggerEngine(DWORD pid);

	void enterDebuggerLoop();
	friend BOOL WINAPI registerSignals(DWORD);

private:
	//TODO: clean up mess with process handle process id and PROCESS_INFORMATION structure
	DEBUG_EVENT debugEvent;
	DWORD processId;
	SmartHandle hProcess;
	states state;
	bool isAttached;
	bool isRunning;
	bool firstBreakpoint; // inspiration from https://github.com/x64dbg/TitanEngine
	bool steppingOut = false;
	std::map<PVOID, BYTE> breakpoints;
	PVOID stepBreakpoint = nullptr;
	PVOID lastBreakpoint = nullptr;
	bool continueTrap = false;

	SmartHandle startup(const wchar_t*);
	void continueIfState();
	void continueExecution();
	void restart();
	void breakSignal();
	void threadsInfo();
	void memoryMappingInfo();
	
	template<class... Args> void debuggerMessage(Args ...);
	template <typename T> std::string asHex(T);
	size_t fromHex(std::string);
	std::string memStateAsString(DWORD);
	std::string memTypeAsString(DWORD);
	std::string argumentAsHex(std::string);
	
	void handleCmd();
	void handleEvent();
	
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
	std::unique_ptr<PEB> loadPeb(SIZE_T* = nullptr);
	std::unique_ptr <RTL_USER_PROCESS_PARAMETERS> loadProcessParameters();
	std::unique_ptr<PEB_LDR_DATA> loadLoaderData();
	std::map<PVOID, std::string> sketchMemory();
	std::map<PVOID, std::string> sketchThreadMemory();
	std::map<PVOID, std::string> sketchModulesSections(PVOID, std::string);
	void sketchMemoryTest();
	
	void dissassembly(PVOID, SIZE_T);
	void setBreakPoint(PVOID);
	void stepOver();
	void stepIn();
	//void stepOut();
	void setSystemBreakpoint(); // TODO: used nowhere
	void setTrapFlag();
	void unsetTrapFlag();
	void showStack(SIZE_T);
	void showGeneralPurposeRegisters();
	void breakpointsInfo();
	void deleteBreakpoint(PVOID);
	void replaceInt3(PVOID, BYTE*, SIZE_T);
	std::map<DWORD, SmartHandle> listActiveThreads();
};
