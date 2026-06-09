#include "symbolObject.h"
#include "dwarfInterp.h"

VariableObject::VariableObject(IDebugBackend* backend, Dwarf_Debug dbg, Dwarf_Loc_Head_c loclist, Dwarf_Unsigned count, Dwarf_Die subprog, Dwarf_Error error, std::string name) :
	backend(backend), dbg(dbg), loclist(loclist), error(error), SymbolObject(name), subprogram(subprog)
{
	Dwarf_Locdesc_c entry = 0;
	Dwarf_Small op = 0;
	for (Dwarf_Unsigned i = 0; i < count; ++i)
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
	if (!name.empty())
		cfa = loadCfa();
}

std::unique_ptr<VariableObject> VariableObject::loadCfa()
{
	Dwarf_Attribute frame;
	Dwarf_Error err = 0;
	int res = dwarf_attr(subprogram, DW_AT_frame_base, &frame, &err);
	if (res == DW_DLV_NO_ENTRY)
		return nullptr;

	Dwarf_Loc_Head_c locl = 0;
	Dwarf_Unsigned cnt = 0;

	res = dwarf_get_loclist_c(frame, &locl, &cnt, &err);
	if (res != DW_DLV_OK)
		return nullptr;

	auto ret = std::make_unique<VariableObject>(backend, dbg, locl, cnt, subprogram, err);
	return ret;
}

std::optional<size_t> VariableObject::value(uint64_t tid, size_t addr)
{
	std::shared_ptr<Location> loc = nullptr;
	for (auto x : locations)
	{
		if (x->inRange(addr))
			loc = x;
	}

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
		Dwarf_Error err = 0;

		int opres = dwarf_get_location_op_value_c(
			loc->lockDescEntry, j, &op,
			&opd1, &opd2, &opd3,
			&offsetforbranch,
			&err);

		if (opres != DW_DLV_OK)
			return std::nullopt;

		switch (op)
		{
		DW_CASES_REG0_TO_15
			return valueFromRegister(tid, op);
		DW_CASES_LIT0_TO_15
			stack.push_back(op - DW_OP_lit0);
			break;
		case DW_OP_stack_value:
			if (!stack.empty())
				return stack.back();
			else
				return std::nullopt;
		case DW_OP_call_frame_cfa:
			return cfaFromFde(tid, addr);
		case DW_OP_fbreg:
			if (cfa)
			{
				auto valOpt = cfa->value(tid, addr);
				if (!valOpt)
					return std::nullopt;
				auto varAddress = valOpt.value() + opd1;
				stack.push_back(readVarFromMemory(varAddress));
			}
			else
				throw std::runtime_error("No cfa in subprogram\n");
			break;
		default:
			break;
		}
	}
	if (!stack.empty())
		return stack.back();
	return std::nullopt;
}

bool VariableObject::inRange(size_t addr)
{
	for (auto x : locations)
	{
		if (x->inRange(addr))
			return true;
	}
	return false;
}

std::optional<size_t> VariableObject::cfaFromFde(uint64_t tid, size_t addr)
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
	Dwarf_Unsigned reg = 0;
	Dwarf_Signed cfaOffset = 0;
	do
	{
		if (subPc)
			low = subPc;

		res = dwarf_get_fde_info_for_cfa_reg3_c(fdeRet, low, &type, &offsetRel,
			&reg, &cfaOffset, &block, &rowPc, &moreRows, &subPc, &error);
	} while (moreRows && low <= addr && subPc <= addr);

	if (res != DW_DLV_OK)
		return std::nullopt;

	auto regVal = valueFromRegister(tid, reg + DW_OP_reg0);
	if (!regVal)
		return std::nullopt;

	return regVal.value() + (offsetRel ? cfaOffset : 0);
}

std::optional<size_t> VariableObject::valueFromRegister(uint64_t tid, short regOpcode)
{
	if (!backend)
		return std::nullopt;

	Registers regs;
	if (!backend->getRegisters(tid, regs))
		return std::nullopt;

	switch (regOpcode)
	{
	case DW_OP_reg0:  return regs.rax;
	case DW_OP_reg1:  return regs.rdx;
	case DW_OP_reg2:  return regs.rcx;
	case DW_OP_reg3:  return regs.rbx;
	case DW_OP_reg4:  return regs.rsi;
	case DW_OP_reg5:  return regs.rdi;
	case DW_OP_reg6:  return regs.rbp;
	case DW_OP_reg7:  return regs.rsp;
	case DW_OP_reg8:  return regs.r8;
	case DW_OP_reg9:  return regs.r9;
	case DW_OP_reg10: return regs.r10;
	case DW_OP_reg11: return regs.r11;
	case DW_OP_reg12: return regs.r12;
	case DW_OP_reg13: return regs.r13;
	case DW_OP_reg14: return regs.r14;
	case DW_OP_reg15: return regs.r15;
	}

	return std::nullopt;
}

size_t VariableObject::readVarFromMemory(uintptr_t address)
{
	if (!backend)
		throw std::runtime_error("No backend attached");

	size_t ret = 0;
	size_t bytesRead = 0;
	if (!backend->readMemory(address, &ret, sizeof(size_t), &bytesRead) || bytesRead != sizeof(size_t))
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
