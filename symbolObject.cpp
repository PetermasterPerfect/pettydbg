#include "symbolObject.h"
#include "dwarfInterp.h"

VariableObject::VariableObject(HANDLE hProcess, Dwarf_Debug dbg, Dwarf_Loc_Head_c loclist, Dwarf_Unsigned count,  Dwarf_Die subprog, Dwarf_Error error, std::string name) :
	hProcess(hProcess), dbg(dbg), loclist(loclist), error(error), SymbolObject(name), subprogram(subprog)
{
	Dwarf_Locdesc_c entry = 0;
	Dwarf_Small op = 0;
	for (int i = 0; i < count; ++i)
	{
		Dwarf_Small loclistKind = 0;
		Dwarf_Small lleValue = 0;
		Dwarf_Unsigned rawval1 = 0;
		Dwarf_Unsigned rawval2 = 0;
		Dwarf_Bool debug_addr_unavailable = 0;
		Dwarf_Addr lopc = 0;
		Dwarf_Addr hipc = 0;
		Dwarf_Unsigned loclist_expr_op_count = 0;
		Dwarf_Locdesc_c locdesc_entry = 0;
		Dwarf_Unsigned expression_offset = 0;
		Dwarf_Unsigned locdesc_offset = 0;

		int res = dwarf_get_locdesc_entry_d(
			loclist, i,
			&lleValue, &rawval1, &rawval2,
			&debug_addr_unavailable,
			&lopc, &hipc,
			&loclist_expr_op_count,
			&locdesc_entry,
			&loclistKind,
			&expression_offset,
			&locdesc_offset,
			&error);
		if (res != DW_DLV_OK)
			throw std::runtime_error("Symbol object constructor failed");

		if (!lopc && subprogram)
		{
			Dwarf_Addr ret = 0;
			Dwarf_Half form = 0;
			Dwarf_Form_Class formclass = (Dwarf_Form_Class)0;
			int res2 = DW_DLV_ERROR;
			res = dwarf_lowpc(subprogram, &lopc, &error);
			if (res == DW_DLV_OK)
			{
				res2 = dwarf_highpc_b(subprogram, &hipc, &form, &formclass, &error);
				if (res2 == DW_DLV_OK && formclass == DW_FORM_CLASS_CONSTANT)
					hipc += lopc;

			}
			else if (res == DW_DLV_ERROR || res2 == DW_DLV_ERROR)
				throw std::runtime_error("Symbol object constructor failed");
		}

		std::shared_ptr<Location> buf = std::make_shared<Location>(lopc, hipc, locdesc_entry, loclist_expr_op_count);
		if (!buf)
			return;
		locations.push_back(buf);

	}
	if (name.size())
		cfa = loadCfa();
}

std::unique_ptr<VariableObject>  VariableObject::loadCfa()
{
	Dwarf_Attribute frame;
	Dwarf_Error error;
	int res = dwarf_attr(subprogram, DW_AT_frame_base, &frame, &error);
	if (res == DW_DLV_NO_ENTRY)
		return nullptr;

	Dwarf_Loc_Head_c loclist = 0;
	Dwarf_Unsigned count = 0;

	res = dwarf_get_loclist_c(frame, &loclist, &count, &error);
	if (res != DW_DLV_OK)
		return nullptr;

	auto ret = std::make_unique<VariableObject>(hProcess, dbg, loclist, count, subprogram, error);
	return ret;
}

std::optional<size_t> VariableObject::value(HANDLE hThread, size_t addr)
{
	std::shared_ptr<Location> loc = nullptr;
	for (auto x : locations)
		if (x->inRange(addr))
			loc = x;

	if (!loc)
		return std::nullopt;

	std::vector<size_t> stack;

	for (Dwarf_Unsigned j = 0; j < loc->lockOpcodesCount; ++j)
	{
		Dwarf_Small op = 0;
		Dwarf_Unsigned opd1 = 0;
		Dwarf_Unsigned opd2 = 0;
		Dwarf_Unsigned opd3 = 0;
		Dwarf_Unsigned offsetforbranch = 0;
		Dwarf_Error error = 0;

		int opres = dwarf_get_location_op_value_c(
			loc->lockDescEntry, j, &op,
			&opd1, &opd2, &opd3,
			&offsetforbranch,
			&error);

		if (opres != DW_DLV_OK)
			return std::nullopt;

		switch (op)
		{
		DW_CASES_REG0_TO_15
			return valueFromRegister(hThread, op);
		DW_CASES_LIT0_TO_15
			stack.push_back(op - DW_OP_lit0);
			break;
		case DW_OP_stack_value:
			if (stack.size())
				return stack.back();
			else 
				return std::nullopt;
		case DW_OP_call_frame_cfa:
			return cfaFromFde(hThread, addr);
		case DW_OP_fbreg:
			if (cfa)
			{
				auto varAddress = cfa->value(hThread, addr).value() + opd1;
				stack.push_back(readVarFromMemory((PVOID)varAddress));
			}
			else
				throw std::runtime_error("No cfa in subprogram\n");
		default: 
			break;
		}
	}
	if (stack.size())
		return stack.back();
	return std::nullopt;
}

bool VariableObject::inRange(size_t addr)
{
	for (auto x : locations)
		if (x->inRange(addr))
			return true;
	return false;
}

std::optional<size_t> VariableObject::cfaFromFde(HANDLE hThread, size_t addr)
{
	Dwarf_Cie* cieData = 0;
	Dwarf_Signed cieCount = 0;
	Dwarf_Fde* fdeData = 0;
	Dwarf_Signed fdeCount = 0;

	int res = dwarf_get_fde_list(dbg, &cieData, &cieCount,
		&fdeData, &fdeCount, &error);
	if (res != DW_DLV_OK)
		return std::nullopt;

	Dwarf_Fde fdeRet = 0;
	Dwarf_Addr low = 0;
	Dwarf_Addr high = 0;
	res = dwarf_get_fde_at_pc(fdeData, addr, &fdeRet, &low, &high, &error);
	if (res != DW_DLV_OK)
		return std::nullopt;

	Dwarf_Small type = 0;
	Dwarf_Unsigned offsetRel = 0;
	Dwarf_Block block;
	Dwarf_Addr rowPc = 0;
	Dwarf_Bool moreRows = 0;
	Dwarf_Addr subPc = 0;
	Dwarf_Unsigned reg;
	Dwarf_Signed cfaOffset;
	do
	{
		if (subPc)
			low = subPc;

		res = dwarf_get_fde_info_for_cfa_reg3_c(fdeRet, low, &type, &offsetRel,
			&reg, &cfaOffset, &block, &rowPc, &moreRows, &subPc, &error);
	} while (moreRows && low <= addr && subPc <= addr);

	if (res != DW_DLV_OK)
		return std::nullopt;

	return valueFromRegister(hThread, reg + DW_OP_reg0).value() + (offsetRel ? cfaOffset : 0);
}


std::optional<size_t> VariableObject::valueFromRegister(HANDLE hThread, short regOpcode)
{
	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(hThread, &ctx))
		return std::nullopt;

	switch (regOpcode)
	{
	case DW_OP_reg0:  return ctx.Rax;
	case DW_OP_reg1:  return ctx.Rdx;
	case DW_OP_reg2:  return ctx.Rcx;
	case DW_OP_reg3:  return ctx.Rbx;
	case DW_OP_reg4:  return ctx.Rsi;
	case DW_OP_reg5:  return ctx.Rdi;
	case DW_OP_reg6:  return ctx.Rbp;
	case DW_OP_reg7:  return ctx.Rsp;
	case DW_OP_reg8:  return ctx.R8;
	case DW_OP_reg9:  return ctx.R9;
	case DW_OP_reg10: return ctx.R10;
	case DW_OP_reg11: return ctx.R11;
	case DW_OP_reg12: return ctx.R12;
	case DW_OP_reg13: return ctx.R13;
	case DW_OP_reg14: return ctx.R14;
	case DW_OP_reg15: return ctx.R15;
	}

	return std::nullopt;
}

size_t VariableObject::readVarFromMemory(PVOID address)
{
	size_t ret;
	SIZE_T len;
	if (!ReadProcessMemory(hProcess, address, &ret, sizeof(size_t), &len))
		throw std::runtime_error("cannot read var from memory");
	return ret;
}

ConstObject::ConstObject(size_t v, Dwarf_Die subprogram, Dwarf_Error error, std::string name) : val(v), SymbolObject(name)
{
	Dwarf_Addr lopc = 0;
	Dwarf_Addr hipc = 0; 
	Dwarf_Half form = 0;
	Dwarf_Form_Class formclass = (Dwarf_Form_Class)0;
	int res = dwarf_lowpc(subprogram, &lopc, &error);
	if (res == DW_DLV_OK)
	{
		res = dwarf_highpc_b(subprogram, &hipc, &form, &formclass, &error);
		if (res == DW_DLV_OK)
		{
			if (formclass == DW_FORM_CLASS_CONSTANT)
				hipc += lopc;
		}
		else
			throw std::runtime_error("Cannot create const object");
		lowpc = lopc;
		highpc = hipc;
	}
	else
		throw std::runtime_error("Cannot create const object");
}

bool ConstObject::inRange(size_t addr)
{
	return addr >= lowpc && addr <= highpc;
}
