#pragma once
#include <vector>
#include <optional>
#include <memory>
#include <stdexcept>
#include "Windows.h"
#include "dwarf.h"
#include "libdwarf.h"


struct Location
{
	size_t lowpc = 0;
	size_t highpc = 0;
	Dwarf_Locdesc_c lockDescEntry;
	Dwarf_Unsigned lockOpcodesCount;
	Location(size_t l, size_t h, Dwarf_Locdesc_c lD, Dwarf_Unsigned lOp) :
		lowpc(l), highpc(h), lockDescEntry(lD), lockOpcodesCount(lOp) {}

	inline bool inRange(size_t addr)
	{
		return addr >= lowpc && addr <= highpc;
	}
};

class SymbolObject
{
public:
	std::string symbolName;
	SymbolObject(std::string symbolName): symbolName(symbolName) {}
	virtual ~SymbolObject() = default;
	virtual bool inRange(size_t ) = 0;
	virtual std::optional<size_t> value(HANDLE, size_t) = 0;
};


class VariableObject : public SymbolObject
{
	std::vector<std::shared_ptr<Location>> locations;
	Dwarf_Debug dbg = 0;
	Dwarf_Error error = 0;
	Dwarf_Die subprogram;
	Dwarf_Loc_Head_c loclist;
	std::unique_ptr<VariableObject> cfa;
	HANDLE hProcess;
	std::optional<size_t> valueFromRegister(HANDLE, short);
	std::optional<size_t> cfaFromFde(HANDLE, size_t);
	size_t readVarFromMemory(PVOID);
	std::unique_ptr<VariableObject> loadCfa();

public:
	VariableObject(HANDLE, Dwarf_Debug, Dwarf_Loc_Head_c, Dwarf_Unsigned, Dwarf_Die, Dwarf_Error, std::string name="");
	~VariableObject()
	{
		if(loclist)
			dwarf_dealloc_loc_head_c(loclist);
	}
	std::optional<size_t> value(HANDLE, size_t) override;
	bool inRange(size_t) override;
};

class ConstObject : public SymbolObject
{
	size_t val = 0;
	size_t lowpc = 0;
	size_t highpc = 0;
public:
	ConstObject(size_t, Dwarf_Die, Dwarf_Error, std::string);// : val(v) {}
	std::optional<size_t> value(HANDLE hThread=nullptr, size_t addr=0) override
	{
		return val;
	}
	bool inRange(size_t) override;
};