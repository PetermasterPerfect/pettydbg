#include "debugger.h"
#ifdef __linux__
#include "linux_debug_backend.h"
#elif defined(_WIN32)
#include "windows_debug_backend.h"
#endif

DebuggerEngine* g_engine = nullptr;

DebuggerEngine::DebuggerEngine(const std::string& cmd)
{
#ifdef __linux__
	backend = std::make_unique<LinuxDebugBackend>();
#elif defined(_WIN32)
	backend = std::make_unique<WindowsDebugBackend>();
#else
	#error "Unsupported platform"
#endif

	if (!backend->startProcess(cmd))
		throw std::runtime_error("Cannot start process");

	std::cout << "Running " << cmd << " with id " << backend->getProcessId() << "\n";
	state = halt;
	debuggerInit();
}

DebuggerEngine::DebuggerEngine(uint64_t pid)
{
#ifdef __linux__
	backend = std::make_unique<LinuxDebugBackend>();
#elif defined(_WIN32)
	backend = std::make_unique<WindowsDebugBackend>();
#else
	#error "Unsupported platform"
#endif

	if (!backend->attachProcess(pid))
		throw std::runtime_error("Cannot attach to process");

	std::cout << "Attaching to process with id " << pid << "\n";
	state = halt;
	debuggerInit();
}

DebuggerEngine::~DebuggerEngine()
{
	if (error && dbg)
		dwarf_dealloc_error(dbg, error);
	if (dbg)
		dwarf_finish(dbg);
}

uint64_t DebuggerEngine::getProcessId() const
{
	return backend ? backend->getProcessId() : 0;
}

void DebuggerEngine::debuggerInit()
{
	initDwarf();
}

template<class... Args>
void DebuggerEngine::debuggerMessage(Args... args)
{
	(std::cout << ... << args) << "\n";
}

template <typename T>
std::string DebuggerEngine::asHex(T num)
{
	std::stringstream sstream;
	sstream << "0x" << std::hex << num;
	return sstream.str();
}

void DebuggerEngine::exit()
{
	if (backend)
		backend->terminate();
	std::exit(0);
}

void DebuggerEngine::breakSignal()
{
	if (backend)
		backend->sendBreakSignal();
}

void DebuggerEngine::threadsInfo()
{
	if (!backend)
		return;
	for (auto tid : backend->listThreads())
		debuggerMessage("Thread - ", tid);
}

void DebuggerEngine::memoryMappingInfo()
{
	if (!backend)
		return;
	for (const auto& line : backend->getMemoryMappings())
		debuggerMessage(line);
}

void DebuggerEngine::handleDebugEvent(unsigned level)
{
	if (!backend)
		return;

	EventInfo event = backend->waitForEvent(state == busy);
	if (event.reason == StopReason::None)
		return;

	currentBreakAddr = event.address;

	if (event.reason == StopReason::Exited)
	{
		state = halt;
		debuggerMessage("Process exited with code ", event.exitStatus, " (signal ", event.signalNumber, ")");
		return;
	}

	if (event.reason == StopReason::Breakpoint)
	{
		uintptr_t bpAddr = event.address;
		Registers regs;
		if (backend->getRegisters(event.threadId, regs))
		{
			// On x86_64, INT3 leaves RIP pointing after the 0xCC
			if (breakpoints.find(regs.rip - 1) != breakpoints.end() || (tempBreakpoint.first && tempBreakpoint.first == regs.rip - 1))
			{
				bpAddr = regs.rip - 1;
				regs.rip = bpAddr;
				backend->setRegisters(event.threadId, regs);
			}
			else if (breakpoints.find(regs.rip) != breakpoints.end() || (tempBreakpoint.first && tempBreakpoint.first == regs.rip))
			{
				bpAddr = regs.rip;
			}
		}

		currentBreakAddr = bpAddr;

		if (tempBreakpoint.first != 0)
		{
			if (breakpoints.find(tempBreakpoint.first) == breakpoints.end())
				deleteTempBreakpoint();
			tempBreakpoint.first = 0;
		}

		if (breakpoints.find(bpAddr) != breakpoints.end())
		{
			// Restore original byte temporarily so the instruction can be executed
			backend->writeMemory(bpAddr, &breakpoints[bpAddr], sizeof(uint8_t));
			lastBreakpoint = bpAddr;
		}

		state = halt;
		debuggerMessage("Breakpoint hit at address ", asHex(bpAddr));

		if (finishing)
		{
			backend->singleStep(event.threadId);
			state = busy;
		}
	}
	else if (event.reason == StopReason::SingleStep)
	{
		if (lastBreakpoint != 0)
		{
			if (breakpoints.find(lastBreakpoint) != breakpoints.end())
			{
				uint8_t int3 = 0xCC;
				backend->writeMemory(lastBreakpoint, &int3, sizeof(uint8_t));
			}
			lastBreakpoint = 0;

			if (continueTrap)
			{
				continueTrap = false;
				continueExecution();
				return;
			}
		}

		state = halt;

		if (finishing)
		{
			finish();
			while (finishing)
				handleDebugEvent(level + 1);
		}
		if (returning)
		{
			Registers regs;
			backend->getRegisters(event.threadId, regs);
			uintptr_t retAddress = 0;
			backend->readMemory(regs.rsp, &retAddress, sizeof(uintptr_t));
			setBreakPoint(retAddress, true);
			continueExecution();
			returning = false;
		}
	}
	else if (event.reason == StopReason::Signal)
	{
		state = halt;
		debuggerMessage("Signal ", event.signalNumber, " at address ", asHex(event.address));
	}
}

void DebuggerEngine::continueExecution()
{
	if (!backend)
		return;

	if (lastBreakpoint != 0)
	{
		continueTrap = true;
		backend->singleStep(backend->getCurrentThreadId());
	}
	else
	{
		backend->continueExecution();
	}
	state = busy;
}

void DebuggerEngine::restart()
{
	if (!backend)
		return;

	if (backend->isAttached())
	{
		debuggerMessage("Cannot restart debuggee. Process was attached.");
		return;
	}

	if (backend->restart())
	{
		state = halt;
		lastBreakpoint = 0;
		tempBreakpoint = {0, 0};
		initDwarf();
	}
}

void DebuggerEngine::showStack(size_t sz)
{
	if (!backend || sz == 0)
		return;

	Registers regs;
	if (!backend->getRegisters(backend->getCurrentThreadId(), regs))
	{
		debuggerMessage("Failed to get registers");
		return;
	}

	std::vector<uintptr_t> stackData(sz, 0);
	size_t bytesRead = 0;
	if (!backend->readMemory(regs.rsp, stackData.data(), sz * sizeof(uintptr_t), &bytesRead))
	{
		debuggerMessage("Failed to read stack memory");
		return;
	}

	for (size_t i = 0; i < sz; ++i)
	{
		debuggerMessage(asHex(regs.rsp + i * sizeof(uintptr_t)), "\t", asHex(stackData[i]));
	}
}

void DebuggerEngine::showGeneralPurposeRegisters()
{
	if (!backend)
		return;

	Registers regs;
	if (!backend->getRegisters(backend->getCurrentThreadId(), regs))
	{
		debuggerMessage("Failed to get registers");
		return;
	}

	debuggerMessage("Rax=", asHex(regs.rax));
	debuggerMessage("Rbx=", asHex(regs.rbx));
	debuggerMessage("Rcx=", asHex(regs.rcx));
	debuggerMessage("Rdx=", asHex(regs.rdx));
	debuggerMessage("Rsi=", asHex(regs.rsi));
	debuggerMessage("Rdi=", asHex(regs.rdi));
	debuggerMessage("Rbp=", asHex(regs.rbp));
	debuggerMessage("Rsp=", asHex(regs.rsp));
	debuggerMessage("R8 =", asHex(regs.r8));
	debuggerMessage("R9 =", asHex(regs.r9));
	debuggerMessage("R10=", asHex(regs.r10));
	debuggerMessage("R11=", asHex(regs.r11));
	debuggerMessage("R12=", asHex(regs.r12));
	debuggerMessage("R13=", asHex(regs.r13));
	debuggerMessage("R14=", asHex(regs.r14));
	debuggerMessage("R15=", asHex(regs.r15));
	debuggerMessage("Rip=", asHex(regs.rip));
}

void DebuggerEngine::disassembly(uintptr_t addr, size_t sz)
{
	if (!backend || sz == 0)
		return;

	std::vector<uint8_t> buf(sz, 0);
	size_t bytesRead = 0;
	if (!backend->readMemory(addr, buf.data(), sz, &bytesRead))
	{
		std::cerr << "Cannot access memory at address " << asHex(addr) << "\n";
		return;
	}
	replaceInt3(addr, buf.data(), sz);

	uintptr_t imageBase = backend->getImageBase();
	size_t imageEnd = imageBase + backend->getImageSize();
	std::pair<std::string, Dwarf_Unsigned> funcInfo;
	Dwarf_Addr functionStart = 0;
	size_t funcOffset = 0;

	if (addr >= imageBase && addr < imageEnd)
	{
		funcOffset = addr - imageBase;
		funcInfo = matchFunctionSymbol(funcOffset, functionStart);
	}

	ZyanU64 runtime_address = static_cast<ZyanU64>(addr);
	ZyanUSize offset = 0;
	ZydisDisassembledInstruction instruction;
	size_t lastFuncOffset = 0;
	bool f = false;

	while (offset < sz && ZYAN_SUCCESS(ZydisDisassembleIntel(
		ZYDIS_MACHINE_MODE_LONG_64,
		runtime_address,
		buf.data() + offset,
		sz - offset,
		&instruction)))
	{
		if (funcInfo.second)
		{
			size_t curInsOff = lastFuncOffset;
			if (!f)
				curInsOff = addr - (imageBase + functionStart) + lastFuncOffset;
			printf("%016" PRIX64 " %s+%" PRIx64 " %s\n", runtime_address, funcInfo.first.c_str(), (uint64_t)curInsOff, instruction.text);
		}
		else
		{
			funcOffset = runtime_address - imageBase;
			funcInfo = matchFunctionSymbol(funcOffset, functionStart);
			if (funcInfo.second)
			{
				lastFuncOffset = 0;
				f = true;
				printf("%016" PRIX64 " %s+%" PRIx64 " %s\n", runtime_address, funcInfo.first.c_str(), (uint64_t)lastFuncOffset, instruction.text);
			}
			else
			{
				printf("%016" PRIX64 "  %s\n", runtime_address, instruction.text);
			}
		}
		offset += instruction.info.length;
		lastFuncOffset = offset;
		if (funcInfo.second < instruction.info.length)
			funcInfo.second = 0;
		else
			funcInfo.second -= instruction.info.length;
		runtime_address += instruction.info.length;
	}
}

void DebuggerEngine::stepOver()
{
	if (!backend)
		return;

	Registers regs;
	if (!backend->getRegisters(backend->getCurrentThreadId(), regs))
		return;

	uintptr_t addr = regs.rip;
	uint8_t buf[30] = {0};
	if (!backend->readMemory(addr, buf, sizeof(buf)))
	{
		debuggerMessage("stepOver readMemory failed");
		return;
	}

	ZydisDisassembledInstruction instruction;
	if (!ZYAN_SUCCESS(ZydisDisassembleIntel(
		ZYDIS_MACHINE_MODE_LONG_64,
		static_cast<ZyanU64>(addr),
		buf,
		sizeof(buf),
		&instruction)))
	{
		return;
	}

	if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
	{
		uintptr_t bpBuf = addr + instruction.info.length;
		setBreakPoint(bpBuf, true);
		continueExecution();
		return;
	}

	stepIn();
}

void DebuggerEngine::finish()
{
	if (!backend)
		return;

	Registers regs;
	if (!backend->getRegisters(backend->getCurrentThreadId(), regs))
		return;

	uintptr_t addr = regs.rip;
	finishing = true;
	uint8_t buf[30] = {0};
	if (!backend->readMemory(addr, buf, sizeof(buf)))
	{
		debuggerMessage("finish readMemory failed");
		return;
	}

	ZydisDisassembledInstruction instruction;
	if (!ZYAN_SUCCESS(ZydisDisassembleIntel(
		ZYDIS_MACHINE_MODE_LONG_64,
		static_cast<ZyanU64>(addr),
		buf,
		sizeof(buf),
		&instruction)))
	{
		return;
	}

	if (instruction.info.mnemonic == ZYDIS_MNEMONIC_RET)
	{
		finishing = false;
		returning = true;
		return;
	}
	else if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
	{
		uintptr_t bpBuf = addr + instruction.info.length;
		setBreakPoint(bpBuf, true);
		continueExecution();
		return;
	}

	stepIn();
}

void DebuggerEngine::stepIn()
{
	if (!backend)
		return;

	if (lastBreakpoint != 0)
	{
		continueTrap = false;
		backend->singleStep(backend->getCurrentThreadId());
	}
	else
	{
		backend->singleStep(backend->getCurrentThreadId());
	}
	state = busy;
}

void DebuggerEngine::deleteTempBreakpoint()
{
	if (!backend || tempBreakpoint.first == 0)
		return;

	backend->writeMemory(tempBreakpoint.first, &tempBreakpoint.second, sizeof(uint8_t));
	tempBreakpoint = {0, 0};
}

void DebuggerEngine::setBreakPoint(uintptr_t breakAddr, bool temp)
{
	if (!backend)
		return;

	if (breakpoints.find(breakAddr) != breakpoints.end())
	{
		debuggerMessage("Breakpoint was already set on given address");
		return;
	}

	uint8_t origByte = 0;
	if (!backend->readMemory(breakAddr, &origByte, sizeof(uint8_t)))
	{
		debuggerMessage("setBreakPoint: cannot read memory at address ", asHex(breakAddr));
		return;
	}

	if (temp)
		tempBreakpoint = std::make_pair(breakAddr, origByte);
	else
		breakpoints[breakAddr] = origByte;

	uint8_t int3 = 0xCC;
	if (!backend->writeMemory(breakAddr, &int3, sizeof(uint8_t)))
	{
		debuggerMessage("setBreakPoint: cannot write breakpoint at address ", asHex(breakAddr));
		return;
	}
}

void DebuggerEngine::breakpointsInfo()
{
	if (breakpoints.empty())
	{
		debuggerMessage("No breakpoints set");
		return;
	}
	for (const auto& bp : breakpoints)
		debuggerMessage("Breakpoint at ", asHex(bp.first));
}

void DebuggerEngine::deleteBreakpoint(uintptr_t addr)
{
	if (!backend)
		return;

	if (breakpoints.find(addr) == breakpoints.end())
	{
		debuggerMessage("No breakpoint at address ", asHex(addr));
		return;
	}

	uint8_t origByte = breakpoints[addr];
	if (!backend->writeMemory(addr, &origByte, sizeof(uint8_t)))
	{
		debuggerMessage("deleteBreakpoint writeMemory failed");
		return;
	}
	breakpoints.erase(addr);
}

void DebuggerEngine::replaceInt3(uintptr_t addr, uint8_t* buf, size_t sz)
{
	for (size_t i = 0; i < sz; i++)
	{
		uintptr_t iAddr = addr + i;
		if (breakpoints.find(iAddr) != breakpoints.end())
			buf[i] = breakpoints[iAddr];
	}
}

std::vector<uint64_t> DebuggerEngine::listActiveThreads()
{
	if (!backend)
		return {};
	return backend->listThreads();
}

void DebuggerEngine::initDwarf()
{
	if (!backend)
		return;

	std::string execPath = backend->getTargetPath();
	if (execPath.empty())
		return;

	char realpathBuf[4096] = {0};
	Dwarf_Handler errhand = 0;
	Dwarf_Ptr errarg = 0;
	int res = dwarf_init_path(execPath.c_str(), realpathBuf, sizeof(realpathBuf),
		DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, &error);
	if (res != DW_DLV_OK)
		std::cerr << "No debugging symbols found.\n";
}

void DebuggerEngine::resetDwarf()
{
	if (error && dbg)
		dwarf_dealloc_error(dbg, error);
	if (dbg)
		dwarf_finish(dbg);
	dbg = 0;
	error = 0;
	initDwarf();
}

std::pair<std::string, Dwarf_Unsigned> DebuggerEngine::matchFunctionSymbol(Dwarf_Unsigned offset, Dwarf_Addr& funcStart)
{
	Address2FunctionSymbol help(offset);
	if (!findSubprogramInCuChain(help))
		return std::make_pair(std::string(), 0);

	funcStart = help.functionStart;
	return std::make_pair(help.funcName, help.size);
}

bool DebuggerEngine::findSubprogramInCuChain(Address2FunctionSymbol& help)
{
	resetDwarf();
	if (!dbg)
		return false;

	Dwarf_Unsigned cuHeaderLen = 0;
	Dwarf_Unsigned abbrevOffset = 0;
	Dwarf_Half addrSize = 0;
	Dwarf_Half versionStamp = 0;
	Dwarf_Half offsetSize = 0;
	Dwarf_Half extSize = 0;
	Dwarf_Unsigned typeoffset = 0;
	Dwarf_Unsigned nextCuOffset = 0;
	Dwarf_Half headerCuType = DW_UT_compile;

	for (int cuNum = 1;; cuNum++)
	{
		Dwarf_Die cuDie = 0;
		Dwarf_Sig8 signature;
		memset(&signature, 0, sizeof(signature));
		int res = dwarf_next_cu_header_e(dbg, 1, &cuDie, &cuHeaderLen,
			&versionStamp, &abbrevOffset, &addrSize, &offsetSize, &extSize,
			&signature, &typeoffset, &nextCuOffset, &headerCuType, &error);

		if (res == DW_DLV_ERROR || res == DW_DLV_NO_ENTRY)
			return false;

		res = findSubprogramInDieChain(cuDie, help, 0);
		help.cuDie = cuDie;
		if (res == FOUND_SUBPROGRAM)
			return true;
		if (res == THIS_CU || res == DW_DLV_ERROR)
			return false;
	}
}

int DebuggerEngine::findSubprogramInDieChain(Dwarf_Die die, Address2FunctionSymbol& help, int level)
{
	int res = checkDieForSubprogram(die, help, level);
	if (res == DW_DLV_ERROR || res == DW_DLV_NO_ENTRY || res == NOT_THIS_CU || res == FOUND_SUBPROGRAM)
		return res;

	Dwarf_Die iterDie = die;
	Dwarf_Die child = 0;
	for (;;)
	{
		Dwarf_Die sibDie = 0;
		int resChild = dwarf_child(iterDie, &child, &error);
		if (resChild == DW_DLV_ERROR)
			return resChild;
		if (resChild == DW_DLV_OK)
		{
			int res2 = findSubprogramInDieChain(child, help, level + 1);
			if (res2 == FOUND_SUBPROGRAM || res2 == NOT_THIS_CU || res2 == DW_DLV_ERROR)
				return res2;
			child = 0;
		}
		resChild = dwarf_siblingof_c(iterDie, &sibDie, &error);
		if (resChild == DW_DLV_ERROR)
			return resChild;
		if (resChild == DW_DLV_NO_ENTRY)
			break;
		if (iterDie != die)
			dwarf_dealloc(dbg, iterDie, DW_DLA_DIE);
		iterDie = sibDie;
		int resSib = checkDieForSubprogram(iterDie, help, level);
		if (resSib == DW_DLV_ERROR || resSib == FOUND_SUBPROGRAM)
			return resSib;
	}
	return DW_DLV_OK;
}

int DebuggerEngine::checkDieForSubprogram(Dwarf_Die die, Address2FunctionSymbol& help, int level)
{
	Dwarf_Half tag = 0;
	int res = dwarf_tag(die, &tag, &error);
	if (res != DW_DLV_OK)
		return res;

	if (tag == DW_TAG_subprogram || tag == DW_TAG_inlined_subroutine)
		return checkSubprogramDetails(die, help);
	else if (tag == DW_TAG_compile_unit || tag == DW_TAG_partial_unit || tag == DW_TAG_type_unit)
	{
		if (level)
			return NOT_THIS_CU;
		return checkCompDir(die, help);
	}
	return DW_DLV_OK;
}

int DebuggerEngine::checkCompDir(Dwarf_Die die, Address2FunctionSymbol& help)
{
	Dwarf_Addr lowPc = 0;
	Dwarf_Addr highPc = 0;
	int res = getHighOffset(die, &lowPc, &highPc, &error);
	if (res != DW_DLV_OK)
		return res;

	lowPc -= backend->getLinkBase();
	if (help.offset >= lowPc && help.offset < lowPc + highPc)
		return THIS_CU;
	return NOT_THIS_CU;
}

int DebuggerEngine::checkSubprogramDetails(Dwarf_Die die, Address2FunctionSymbol& help)
{
	Dwarf_Addr lowPc = 0;
	Dwarf_Addr highPc = 0;
	int res = getHighOffset(die, &lowPc, &highPc, &error);
	if (res != DW_DLV_OK)
		return res;

	lowPc -= backend->getLinkBase();
	if (help.offset < lowPc || help.offset >= lowPc + highPc)
		return DW_DLV_OK;

	char* name = nullptr;
	help.size = highPc;
	if (help.offset > lowPc)
		help.size -= help.offset - lowPc;
	help.functionStart = lowPc;

	res = dwarf_diename(die, &name, &error);
	if (res == DW_DLV_OK)
		help.funcName = std::string(name);
	else
	{
		if (nameFromAbstract(die, help, &name))
			help.funcName = std::string(name);
		else
			return res;
	}
	return FOUND_SUBPROGRAM;
}

bool DebuggerEngine::nameFromAbstract(Dwarf_Die die, Address2FunctionSymbol& help, char** name)
{
	Dwarf_Die abrootdie = 0;
	Dwarf_Attribute ab_attr = 0;
	Dwarf_Off ab_offset = 0;

	if (dwarf_attr(die, DW_AT_abstract_origin, &ab_attr, &error))
		return false;
	if (dwarf_global_formref(ab_attr, &ab_offset, &error))
	{
		dwarf_dealloc(dbg, ab_attr, DW_DLA_ATTR);
		return false;
	}
	dwarf_dealloc(dbg, ab_attr, DW_DLA_ATTR);
	if (dwarf_offdie_b(dbg, ab_offset, 1, &abrootdie, &error))
		return false;
	int res = dwarf_diename(abrootdie, name, &error);
	dwarf_dealloc_die(abrootdie);
	return !res;
}

int DebuggerEngine::getHighOffset(Dwarf_Die die, Dwarf_Addr* lowpc, Dwarf_Addr* highpc, Dwarf_Error* err)
{
	Dwarf_Half form = 0;
	Dwarf_Form_Class formclass = static_cast<Dwarf_Form_Class>(0);
	int res = dwarf_lowpc(die, lowpc, err);
	if (res == DW_DLV_OK)
	{
		res = dwarf_highpc_b(die, highpc, &form, &formclass, err);
		if (res == DW_DLV_OK)
		{
			if (formclass != DW_FORM_CLASS_CONSTANT)
				*highpc -= *lowpc;
		}
	}
	return res;
}

void DebuggerEngine::mapLocalVariables(Dwarf_Unsigned off)
{
	resetDwarf();
	if (!dbg)
		return;

	Address2Locals help(off);
	Dwarf_Unsigned cuHeaderLen = 0;
	Dwarf_Unsigned abbrevOffset = 0;
	Dwarf_Half addrSize = 0;
	Dwarf_Half versionStamp = 0;
	Dwarf_Half offsetSize = 0;
	Dwarf_Half extSize = 0;
	Dwarf_Unsigned typeoffset = 0;
	Dwarf_Unsigned nextCuOffset = 0;
	Dwarf_Half headerCuType = DW_UT_compile;

	for (int cuNum = 1;; cuNum++)
	{
		Dwarf_Die cuDie = 0;
		Dwarf_Sig8 signature;
		memset(&signature, 0, sizeof(signature));
		int res = dwarf_next_cu_header_e(dbg, 1, &cuDie, &cuHeaderLen,
			&versionStamp, &abbrevOffset, &addrSize, &offsetSize, &extSize,
			&signature, &typeoffset, &nextCuOffset, &headerCuType, &error);

		if (res == DW_DLV_ERROR)
			throw std::runtime_error("Cannot dwarf init");
		if (res == DW_DLV_NO_ENTRY)
			break;

		findVariablesInSubprogram(cuDie, help, 0);
	}
}

int DebuggerEngine::findVariablesInSubprogram(Dwarf_Die die, Address2Locals& help, int level)
{
	int res = checkDieForSubprogram(die, help, level);
	if (res == DW_DLV_ERROR || res == DW_DLV_NO_ENTRY || res == NOT_THIS_CU)
		return res;
	if (res == FOUND_SUBPROGRAM)
	{
		scanSubprogramForVariables(die, help, 0);
		return res;
	}

	Dwarf_Die iterDie = die;
	Dwarf_Die child = 0;
	for (;;)
	{
		Dwarf_Die sibDie = 0;
		int resChild = dwarf_child(iterDie, &child, &error);
		if (resChild == DW_DLV_ERROR)
			return resChild;
		if (resChild == DW_DLV_OK)
		{
			int res2 = findVariablesInSubprogram(child, help, level + 1);
			if (res2 == FOUND_SUBPROGRAM || res2 == NOT_THIS_CU || res2 == DW_DLV_ERROR)
				return res2;
			child = 0;
		}
		resChild = dwarf_siblingof_c(iterDie, &sibDie, &error);
		if (resChild == DW_DLV_ERROR)
			return resChild;
		if (resChild == DW_DLV_NO_ENTRY)
			break;
		if (iterDie != die)
			dwarf_dealloc(dbg, iterDie, DW_DLA_DIE);
		iterDie = sibDie;
		int resSib = checkDieForSubprogram(iterDie, help, level);
		if (resSib == FOUND_SUBPROGRAM)
		{
			scanSubprogramForVariables(iterDie, help, 0);
			return resSib;
		}
		else if (resSib == DW_DLV_ERROR)
			return resSib;
	}
	return res;
}

int DebuggerEngine::checkDieForSubprogram(Dwarf_Die die, Address2Locals& help, int level)
{
	Dwarf_Half tag = 0;
	int res = dwarf_tag(die, &tag, &error);
	if (res != DW_DLV_OK)
		return res;

	if (tag == DW_TAG_subprogram || tag == DW_TAG_inlined_subroutine)
	{
		res = checkSubprogramDetails(die, help);
		if (res == FOUND_SUBPROGRAM)
			return res;
	}
	else if (tag == DW_TAG_compile_unit || tag == DW_TAG_partial_unit || tag == DW_TAG_type_unit)
	{
		if (level)
			return NOT_THIS_CU;
		return checkCompDir(die, help);
	}
	return DW_DLV_OK;
}

int DebuggerEngine::checkCompDir(Dwarf_Die die, Address2Locals& help)
{
	Dwarf_Addr lowPc = 0;
	Dwarf_Addr highPc = 0;
	int res = getHighOffset(die, &lowPc, &highPc, &error);
	if (res != DW_DLV_OK)
		return res;

	lowPc -= backend->getLinkBase();
	if (help.offset >= lowPc && help.offset < lowPc + highPc)
		return THIS_CU;
	return NOT_THIS_CU;
}

int DebuggerEngine::checkSubprogramDetails(Dwarf_Die die, Address2Locals& help)
{
	Dwarf_Addr lowPc = 0;
	Dwarf_Addr highPc = 0;
	int res = getHighOffset(die, &lowPc, &highPc, &error);
	if (res != DW_DLV_OK)
		return res;

	lowPc -= backend->getLinkBase();
	if (help.offset < lowPc || help.offset >= lowPc + highPc)
		return DW_DLV_OK;

	help.subprogram = die;
	return FOUND_SUBPROGRAM;
}

int DebuggerEngine::scanSubprogramForVariables(Dwarf_Die die, Address2Locals& help, int level)
{
	extractVariableFromTag(die, help);
	Dwarf_Die child = 0;
	int res = dwarf_child(die, &child, &error);
	if (res == DW_DLV_OK)
	{
		for (;;)
		{
			scanSubprogramForVariables(child, help, level + 1);
			Dwarf_Die sibling = 0;
			res = dwarf_siblingof_c(child, &sibling, &error);
			dwarf_dealloc(dbg, child, DW_DLA_DIE);
			if (res == DW_DLV_NO_ENTRY)
				break;
			if (res == DW_DLV_ERROR)
				return res;
			child = sibling;
		}
	}
	return DW_DLV_OK;
}

void DebuggerEngine::extractVariableFromTag(Dwarf_Die die, Address2Locals& help)
{
	Dwarf_Half tag = 0;
	int res = dwarf_tag(die, &tag, &error);
	if (res != DW_DLV_OK)
		return;

	if (tag == DW_TAG_variable || tag == DW_TAG_formal_parameter)
	{
		std::pair<Dwarf_Die, Dwarf_Die> dies = std::make_pair(die, static_cast<Dwarf_Die>(0));
		Dwarf_Attribute attr = 0;
		res = dwarf_attr(die, DW_AT_abstract_origin, &attr, &error);
		if (res == DW_DLV_OK)
		{
			Dwarf_Off off = 0;
			Dwarf_Bool isInfo = 0;
			res = dwarf_formref(attr, &off, &isInfo, &error);
			if (res == DW_DLV_OK)
			{
				Dwarf_Die abstractDie = 0;
				res = dwarf_offdie_b(dbg, off, isInfo, &abstractDie, &error);
				if (res == DW_DLV_OK)
					dies.second = abstractDie;
			}
		}

		auto name = varNameWithAbstractOrigin(dies);
		res = attrWithhAbstractOrigin(dies, DW_AT_location, &attr);
		if (res == DW_DLV_OK)
		{
			Dwarf_Loc_Head_c loclist = 0;
			Dwarf_Unsigned count = 0;
			res = dwarf_get_loclist_c(attr, &loclist, &count, &error);
			if (res == DW_DLV_OK && name)
			{
				auto sym = std::make_shared<VariableObject>(backend.get(), dbg, loclist, count, help.subprogram, error, name.value());
				localVariables.push_back(std::move(sym));
			}
		}
		else if (attrWithhAbstractOrigin(dies, DW_AT_const_value, &attr) == DW_DLV_OK)
		{
			Dwarf_Unsigned val = 0;
			res = dwarf_formudata(attr, &val, &error);
			if (res == DW_DLV_OK && name)
			{
				auto sym = std::make_shared<ConstObject>(val, help.subprogram, error, name.value());
				localVariables.push_back(std::move(sym));
			}
		}
	}
}

int DebuggerEngine::attrWithhAbstractOrigin(std::pair<Dwarf_Die, Dwarf_Die> dies, Dwarf_Half attrNum, Dwarf_Attribute* attr)
{
	int res = dwarf_attr(dies.first, attrNum, attr, &error);
	if (res == DW_DLV_OK)
		return res;
	if (dies.second)
		return dwarf_attr(dies.second, attrNum, attr, &error);
	return res;
}

std::optional<std::string> DebuggerEngine::varNameWithAbstractOrigin(std::pair<Dwarf_Die, Dwarf_Die> dies)
{
	char* name = nullptr;
	int res = dwarf_diename(dies.first, &name, &error);
	if (res == DW_DLV_OK)
		return std::string(name);
	else
	{
		Dwarf_Die abrootdie = 0;
		Dwarf_Attribute ab_attr = 0;
		Dwarf_Off ab_offset = 0;
		if (dwarf_attr(dies.first, DW_AT_abstract_origin, &ab_attr, &error))
			return std::nullopt;
		if (dwarf_global_formref(ab_attr, &ab_offset, &error))
		{
			dwarf_dealloc(dbg, ab_attr, DW_DLA_ATTR);
			return std::nullopt;
		}
		dwarf_dealloc(dbg, ab_attr, DW_DLA_ATTR);
		if (dwarf_offdie_b(dbg, ab_offset, 1, &abrootdie, &error))
			return std::nullopt;
		res = dwarf_diename(abrootdie, &name, &error);
		if (res == DW_DLV_OK)
		{
			std::string ret(name);
			dwarf_dealloc_die(abrootdie);
			return ret;
		}
		dwarf_dealloc_die(abrootdie);
	}
	return std::nullopt;
}

void DebuggerEngine::updateLocalVariables(size_t addr)
{
	if (!backend)
		return;

	uintptr_t imageBase = backend->getImageBase();
	size_t imageEnd = imageBase + backend->getImageSize();

	if (addr >= imageBase && addr < imageEnd)
	{
		size_t offset = addr - imageBase;
		auto it = localVariables.begin();
		localVariables.erase(std::remove_if(localVariables.begin(), localVariables.end(),
			[=](std::shared_ptr<SymbolObject> const& p)
			{
				return !p->value(backend->getCurrentThreadId(), offset);
			}), localVariables.end());

		if (localVariables.empty())
			mapLocalVariables(offset);
	}
	else
	{
		localVariables.clear();
	}
}

void DebuggerEngine::printLocal(const std::string& varName)
{
	if (!backend)
		return;

	uintptr_t breakAddr = currentBreakAddr;
	size_t addr = backend->getLinkBase() + breakAddr - backend->getImageBase();
	updateLocalVariables(breakAddr);

	for (auto& x : localVariables)
	{
		if (x->symbolName == varName)
		{
			auto val = x->value(backend->getCurrentThreadId(), addr);
			if (val)
				std::cout << varName << " = " << val.value() << "\n";
			else
				std::cerr << "Cannot retrieve " << varName << " value\n";
		}
	}
}

void DebuggerEngine::showLocals()
{
	for (auto& x : localVariables)
	{
		if (auto v = std::dynamic_pointer_cast<VariableObject>(x))
			std::cout << "varobj: " << v->symbolName << "\n";
		else if (auto v = std::dynamic_pointer_cast<ConstObject>(x))
			std::cout << "constobj: " << v->symbolName << "\n";
	}
}

std::optional<std::string> DebuggerEngine::findCurrentSource(size_t lines)
{
	if (!backend)
		return std::nullopt;

	Dwarf_Unsigned off = static_cast<Dwarf_Unsigned>(currentBreakAddr - backend->getImageBase());
	return findFunctionSource(off, lines);
}

std::optional<std::string> DebuggerEngine::findFunctionSource(Dwarf_Unsigned offset, size_t lines)
{
	Address2FunctionSymbol help(offset);
	if (!findSubprogramInCuChain(help))
		return std::nullopt;

	Dwarf_Unsigned version = 0;
	Dwarf_Small tableCount = 0;
	Dwarf_Line_Context context = 0;

	int res = dwarf_srclines_b(help.cuDie, &version, &tableCount, &context, &error);
	if (res != DW_DLV_OK)
		return std::nullopt;

	Dwarf_Line* lineBuf = nullptr;
	Dwarf_Signed lineCount = 0;
	res = dwarf_srclines_from_linecontext(context, &lineBuf, &lineCount, &error);
	if (res != DW_DLV_OK)
		return std::nullopt;

	size_t addressLineNumber = 0;
	Dwarf_Signed idx = findAddressLineIndex(lineBuf, lineCount, &addressLineNumber, help);
	if (idx == -1)
		return std::nullopt;

	lines = lines >= static_cast<size_t>(lineCount) ? lineCount / 2 : lines / 2;

	Dwarf_Signed startIdx = idx >= static_cast<Dwarf_Signed>(lines) ? idx - lines : 0;
	Dwarf_Signed endIdx = idx >= lineCount - static_cast<Dwarf_Signed>(lines) - 1 ? lineCount - 1 : idx + lines;

	char* srcName = nullptr;
	res = dwarf_linesrc(lineBuf[idx], &srcName, &error);
	if (res != DW_DLV_OK)
		return std::nullopt;

	std::pair<size_t, size_t> lineRange;
	res = dwarf_lineno(lineBuf[startIdx], (Dwarf_Unsigned*)&lineRange.first, &error);
	if (res != DW_DLV_OK)
		return std::nullopt;

	res = dwarf_lineno(lineBuf[endIdx], (Dwarf_Unsigned*)&lineRange.second, &error);
	if (res != DW_DLV_OK)
		return std::nullopt;

	std::ifstream file(correctWslPath(srcName));
	if (!file)
		return std::nullopt;

	std::string line;
	std::stringstream ret;
	size_t lineNum = 1;
	while (std::getline(file, line))
	{
		if (lineNum >= lineRange.first && lineNum <= lineRange.second)
		{
			if (lineNum == addressLineNumber)
				ret << lineNum << " => " << line << "\n";
			else
				ret << lineNum << "    " << line << "\n";
		}
		lineNum++;
	}
	if (!ret.str().empty())
		return ret.str();
	return std::nullopt;
}

Dwarf_Signed DebuggerEngine::findAddressLineIndex(Dwarf_Line* lineBuf,
	Dwarf_Signed lineCount, size_t* lineNum, Address2FunctionSymbol& help)
{
	size_t previous = 0;
	Dwarf_Signed ret = -1;
	for (Dwarf_Signed i = 0; i < lineCount && ret == -1; i++)
	{
		Dwarf_Addr retAddr = 0;
		int res = dwarf_lineaddr(lineBuf[i], &retAddr, &error);
		if (res != DW_DLV_OK)
			continue;

		size_t offset = retAddr - backend->getLinkBase();
		if (i)
		{
			if (offset == help.offset)
				ret = i;
			else if (help.offset > previous && help.offset < offset)
				ret = i - 1;
		}
		else if (offset == help.offset)
		{
			ret = 0;
		}
		previous = offset;
	}
	if (ret != -1)
		dwarf_lineno(lineBuf[ret], (Dwarf_Unsigned*)lineNum, &error);

	return ret;
}

std::string DebuggerEngine::correctWslPath(std::string input)
{
#ifdef _WIN32
	std::string path = input;
	std::string prefix = "/mnt/c";
	if (path.rfind(prefix, 0) == 0)
	{
		path.replace(0, prefix.size(), "C:\\");
	}
	std::replace(path.begin(), path.end(), '/', '\\');
	return path;
#else
	return input;
#endif
}
