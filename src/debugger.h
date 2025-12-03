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
#include <algorithm>
#include "peb.h"
#include "unicodeStringEx.h"
#include "thread_info.h"
#include <inttypes.h>
#include <Zydis/Zydis.h>
#include <optional>
#include "dwarf.h"
#include "libdwarf.h"
#include "symbolObject.h"

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
	DebuggerEngine(const wchar_t *);
	DebuggerEngine(DWORD pid);
	~DebuggerEngine();

	bool isBusy() const { return state == busy; };
	friend BOOL WINAPI registerSignals(DWORD);


	void exit();
	void handleDebugEvent(unsigned level=0);
	void continueExecution();
	void restart();
	void breakSignal();
	void threadsInfo();
	void memoryMappingInfo();
	void disassembly(PVOID, SIZE_T);
	void setBreakPoint(PVOID, bool temp=false);
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
	void printLocal(std::string);
	void showLocals();
	std::optional<std::string> findCurrentSource(size_t);

private:
	struct Address2FunctionSymbol
	{
		std::string funcName;
		Dwarf_Unsigned offset;
		Dwarf_Unsigned size = 0;
		Dwarf_Addr functionStart = 0;
		Dwarf_Die cuDie = 0;
		Address2FunctionSymbol(Dwarf_Unsigned off) : offset(off) {}
	};
	
	struct Address2Locals
	{
		Dwarf_Unsigned offset;
		Dwarf_Die subprogram = 0;

		Address2Locals(Dwarf_Unsigned off) : offset(off) {}
	};

	Dwarf_Debug dbg;
	Dwarf_Error error = 0;

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
	bool returning = false;
	std::map<PVOID, BYTE> breakpoints;
	std::pair<PVOID, BYTE> tempBreakpoint;
	PVOID lastBreakpoint = nullptr;
	bool continueTrap = false;
	std::vector<std::shared_ptr<SymbolObject>> localVariables;

	SmartHandle startup(const wchar_t*);
	void continueIfState(states);
	void debuggerInit();
	template<class... Args> void debuggerMessage(Args ...);
	template <typename T> std::string asHex(T);
	std::string memStateAsString(DWORD);
	std::string memTypeAsString(DWORD);
	
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
	void deleteTempBreakpoint();
	
	PVOID getImageBase();
	void loadPeNtHeader();
	std::unique_ptr<char[]> getFullExecPath();
	void updateLocalVariables(size_t);
	inline SmartHandle getDebugEventsThread() { return  std::move(listActiveThreads()[debugEvent.dwThreadId]);  }

	void initDwarf();
	void resetDwarf();
	int findSubprogramInDieChain(Dwarf_Die, Address2FunctionSymbol&, int);
	bool findSubprogramInCuChain(Address2FunctionSymbol&);

	std::pair<std::string, Dwarf_Unsigned> matchFunctionSymbol(Dwarf_Unsigned, Dwarf_Addr&);
	
	void mapLocalVariables(Dwarf_Unsigned);

	int checkDieForSubprogram(Dwarf_Die, Address2FunctionSymbol&, int);
	int checkDieForSubprogram(Dwarf_Die, Address2Locals&, int);
	int checkSubprogramDetails(Dwarf_Die, Address2FunctionSymbol&);
	int checkSubprogramDetails(Dwarf_Die, Address2Locals&);
	int checkCompDir(Dwarf_Die, Address2FunctionSymbol&);
	int checkCompDir(Dwarf_Die, Address2Locals&);

	int getHighOffset(Dwarf_Die, Dwarf_Addr*, Dwarf_Addr*, Dwarf_Error*);
	bool nameFromAbstract(Dwarf_Die, Address2FunctionSymbol&, char**);

	int findVariablesInSubprogram(Dwarf_Die, Address2Locals&, int);
	int scanSubprogramForVariables(Dwarf_Die die, Address2Locals& help, int level);
	void extractVariableFromTag(Dwarf_Die, Address2Locals&);
	int attrWithhAbstractOrigin(std::pair<Dwarf_Die, Dwarf_Die>, Dwarf_Half, Dwarf_Attribute*);
	std::optional<std::string> varNameWithAbstractOrigin(std::pair<Dwarf_Die, Dwarf_Die>);
	Dwarf_Signed DebuggerEngine::findAddressLineIndex(Dwarf_Line*, Dwarf_Signed, size_t*, Address2FunctionSymbol&);

	std::optional<std::string> findFunctionSource(Dwarf_Unsigned, size_t);
	std::string correctWslPath(std::string);

};
