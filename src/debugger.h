#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <inttypes.h>
#include <Zydis/Zydis.h>
#include "dwarf.h"
#include "libdwarf.h"
#include "symbolObject.h"
#include "debug_backend.h"

#define NOT_THIS_CU 0x100
#define THIS_CU 0x101
#define FOUND_SUBPROGRAM 0x102

enum states { halt, busy };

class DebuggerEngine
{
public:
	DebuggerEngine(const std::string& cmd);
	DebuggerEngine(uint64_t pid);
	~DebuggerEngine();

	bool isBusy() const { return state == busy; }
	uint64_t getProcessId() const;

	void exit();
	void handleDebugEvent(unsigned level = 0);
	void continueExecution();
	void restart();
	void breakSignal();
	void threadsInfo();
	void memoryMappingInfo();
	void disassembly(uintptr_t addr, size_t sz);
	void setBreakPoint(uintptr_t addr, bool temp = false);
	void stepOver();
	void stepIn();
	void finish();
	void showStack(size_t sz);
	void showGeneralPurposeRegisters();
	void breakpointsInfo();
	void deleteBreakpoint(uintptr_t addr);
	std::vector<uint64_t> listActiveThreads();
	void printLocal(const std::string& varName);
	void showLocals();
	std::optional<std::string> findCurrentSource(size_t lines);

	IDebugBackend* getBackend() { return backend.get(); }

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

	std::unique_ptr<IDebugBackend> backend;
	states state = halt;

	Dwarf_Debug dbg = 0;
	Dwarf_Error error = 0;

	bool finishing = false;
	bool returning = false;
	std::map<uintptr_t, uint8_t> breakpoints;
	std::pair<uintptr_t, uint8_t> tempBreakpoint = {0, 0};
	uintptr_t lastBreakpoint = 0;
	bool continueTrap = false;
	std::vector<std::shared_ptr<SymbolObject>> localVariables;

	uintptr_t currentBreakAddr = 0;

	void debuggerInit();
	template<class... Args> void debuggerMessage(Args... args);
	template <typename T> std::string asHex(T num);
	void replaceInt3(uintptr_t addr, uint8_t* buf, size_t sz);
	void deleteTempBreakpoint();

	void initDwarf();
	void resetDwarf();
	int findSubprogramInDieChain(Dwarf_Die die, Address2FunctionSymbol& help, int level);
	bool findSubprogramInCuChain(Address2FunctionSymbol& help);

	std::pair<std::string, Dwarf_Unsigned> matchFunctionSymbol(Dwarf_Unsigned offset, Dwarf_Addr& funcStart);
	void mapLocalVariables(Dwarf_Unsigned offset);

	int checkDieForSubprogram(Dwarf_Die die, Address2FunctionSymbol& help, int level);
	int checkDieForSubprogram(Dwarf_Die die, Address2Locals& help, int level);
	int checkSubprogramDetails(Dwarf_Die die, Address2FunctionSymbol& help);
	int checkSubprogramDetails(Dwarf_Die die, Address2Locals& help);
	int checkCompDir(Dwarf_Die die, Address2FunctionSymbol& help);
	int checkCompDir(Dwarf_Die die, Address2Locals& help);

	int getHighOffset(Dwarf_Die die, Dwarf_Addr* lowpc, Dwarf_Addr* highpc, Dwarf_Error* err);
	bool nameFromAbstract(Dwarf_Die die, Address2FunctionSymbol& help, char** name);

	int findVariablesInSubprogram(Dwarf_Die die, Address2Locals& help, int level);
	int scanSubprogramForVariables(Dwarf_Die die, Address2Locals& help, int level);
	void extractVariableFromTag(Dwarf_Die die, Address2Locals& help);
	int attrWithhAbstractOrigin(std::pair<Dwarf_Die, Dwarf_Die> dies, Dwarf_Half attrNum, Dwarf_Attribute* attr);
	std::optional<std::string> varNameWithAbstractOrigin(std::pair<Dwarf_Die, Dwarf_Die> dies);
	Dwarf_Signed findAddressLineIndex(Dwarf_Line* lineBuf, Dwarf_Signed lineCount, size_t* lineNum, Address2FunctionSymbol& help);

	std::optional<std::string> findFunctionSource(Dwarf_Unsigned offset, size_t lines);
	std::string correctWslPath(std::string input);
	void updateLocalVariables(size_t addr);
};
