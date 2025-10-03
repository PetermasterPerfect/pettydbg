#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <sstream>
#include <map>
#include <vector>
#include <memory>
#include <stdexcept>
#include <iomanip>
#include <fstream>
#include "peb.h"
#include "unicodeStringEx.h"
#include "thread_info.h"
#include <inttypes.h>
#include <Zydis/Zydis.h>
#include "dwarf.h"
#include "libdwarf.h"

#define INT_1 0xCD01
#define INT_3 0xCC

#define NOT_THIS_CU 0x100
#define THIS_CU 0x101
#define FOUND_SUBPROGRAM 0x102

class DebuggerEngine;
enum states{halt, busy};

struct SmartHandleDeleter
{
	BOOL operator()(HANDLE h) const {
		return CloseHandle(h);
	}
};

using SmartHandle = std::unique_ptr<void, SmartHandleDeleter>;

class DebuggerEngine
{
public:
	DebuggerEngine(wchar_t *);
	DebuggerEngine(DWORD pid);

	bool isBusy() const { return state == busy; };
	friend BOOL WINAPI registerSignals(DWORD);

	void handleDebugEvent();
	void continueExecution();
	void restart();
	void breakSignal();
	void threadsInfo();
	void memoryMappingInfo();
	void disassembly(PVOID, SIZE_T);
	void setBreakPoint(PVOID);
	void stepOver();
	void stepIn();
	void finish();
	void setTrapFlag();
	void unsetTrapFlag();
	void showStack(SIZE_T);
	void showGeneralPurposeRegisters();
	void breakpointsInfo();
	void deleteBreakpoint(PVOID);
	std::map<DWORD, SmartHandle> listActiveThreads();
	std::pair<std::string, Dwarf_Unsigned> matchFunctionSymbol(Dwarf_Unsigned, Dwarf_Addr&);

private:
	struct Address2FunctionSymbol
	{
		Dwarf_Debug dbg = 0;
		std::string funcName;
		Dwarf_Unsigned offset;
		Dwarf_Unsigned size = 0;
		Dwarf_Error error = 0;
		Dwarf_Addr functionStart = 0;
		Address2FunctionSymbol(Dwarf_Unsigned off) : offset(off) {}

		~Address2FunctionSymbol()
		{
			if (error)
			{
				if(dbg)
					dwarf_dealloc_error(dbg, error);
			}
			if(dbg)
				dwarf_finish(dbg);
		}
	};
	//TODO: clean up mess with process handle process id and PROCESS_INFORMATION structure
	DEBUG_EVENT debugEvent;
	DWORD processId;
	SmartHandle hProcess;
	PVOID imageBase;
	IMAGE_NT_HEADERS ntHdr;
	states state = halt;
	bool isAttached;
	bool isRunning;
	bool firstBreakpoint = false; // inspiration from https://github.com/x64dbg/TitanEngine
	bool finishing = false;
	std::map<PVOID, BYTE> breakpoints;
	PVOID stepBreakpoint = nullptr;
	PVOID lastBreakpoint = nullptr;
	bool continueTrap = false;

	SmartHandle startup(const wchar_t*);
	void continueIfState(states);
	
	template<class... Args> void debuggerMessage(Args ...);
	template <typename T> std::string asHex(T);
	size_t fromHex(std::string);
	std::string memStateAsString(DWORD);
	std::string memTypeAsString(DWORD);
	std::string argumentAsHex(std::string);
	
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
	void replaceInt3(PVOID, BYTE*, SIZE_T);
	
	PVOID getImageBase();
	void loadPeNtHeader();
	std::unique_ptr<char[]> getFullExecPath();
	int findSubprogramInDieChain(Dwarf_Die, Address2FunctionSymbol&, int);
	bool findSubprogramInCuChain(Address2FunctionSymbol&);
	int checkDieForSubprogram(Dwarf_Die, Address2FunctionSymbol&, int);
	int checkSubprogramDetails(Dwarf_Die, Address2FunctionSymbol&);
	int getHighOffset(Dwarf_Die, Dwarf_Addr*, Dwarf_Addr*, Dwarf_Error*);
	bool nameFromAbstract(Dwarf_Die, Address2FunctionSymbol&, char**);
	int checkCompDir(Dwarf_Die, Address2FunctionSymbol&);
};
