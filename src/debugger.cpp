#include "debugger.h"
#include <cstdlib>

DebuggerEngine* g_engine;

BOOL WINAPI registerSignals(DWORD dwCtrlType)
{
	if (dwCtrlType == CTRL_C_EVENT)
		goto KILL;
	else if (dwCtrlType == CTRL_BREAK_EVENT)
	{
		if (g_engine->isBusy())
		{
			g_engine->breakSignal();
			goto RET;
		}
		else
			goto KILL;
	}
KILL:
	DebugActiveProcessStop(g_engine->processId);
	ExitProcess(0xcc);
RET:
	return TRUE;
}

DebuggerEngine::DebuggerEngine(const wchar_t *cmd)
{
	hProcess = startup(cmd);
	if(hProcess == NULL)
		throw std::runtime_error("Cannot start process\n");

	printf("Running %ls with id %i\n", cmd, GetProcessId(hProcess.get()));
	firstBreakpoint = true;
	isAttached = false;
	debuggerInit();
}

DebuggerEngine::DebuggerEngine(DWORD pid)
{
	hProcess = SmartHandle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid));
	if (hProcess == NULL)
		throw std::runtime_error("Cannot run process\n");

	if(!DebugActiveProcess(pid))
		throw std::runtime_error("Cannot debug process\n");

	debuggerMessage("Attaching to process with id ", pid);
	processId = pid;
	isAttached = true;
	debuggerInit();
}

DebuggerEngine::~DebuggerEngine()
{
	if (error)
	{
		if (dbg)
			dwarf_dealloc_error(dbg, error);
	}
	if(dbg)
		dwarf_finish(dbg);
}

void DebuggerEngine::debuggerInit()
{
	imageBase = getImageBase();
	loadPeNtHeader();
	initDwarf();
}

template<class... Args> void DebuggerEngine::debuggerMessage(Args... args)
{
	(std::cout << ... << args) << std::endl;
}


template <typename T> std::string DebuggerEngine::asHex(T num)
{
	std::stringstream sstream;
	sstream << "0x" << std::hex << num;
	return sstream.str();
}

 void DebuggerEngine::handleDebugEvent(unsigned level)
{
	 if (!WaitForDebugEvent(&debugEvent, 10))
		 return;

	switch(debugEvent.dwDebugEventCode)
	{
		case EXCEPTION_DEBUG_EVENT:
		{
			if(!level)
				exceptionEvent();
			EXCEPTION_DEBUG_INFO& exception = debugEvent.u.Exception;
			PVOID breakAddr = exception.ExceptionRecord.ExceptionAddress;
			switch( exception.ExceptionRecord.ExceptionCode)
			{
				case STATUS_BREAKPOINT:
				{
					if(firstBreakpoint)
					{
						std::map<PVOID, BYTE> buf(breakpoints);
						breakpoints.clear();
						for(auto breakpoint : buf)
							setBreakPoint(breakpoint.first);

						firstBreakpoint = false;
					}
					if(breakpoints.find(breakAddr) != breakpoints.end() || tempBreakpoint.first)
					{
						SmartHandle hT = getDebugEventsThread();
						if(!hT)
							debuggerMessage("ht ", GetLastError());
						CONTEXT ctx;
						ctx.ContextFlags = CONTEXT_CONTROL;

						if(!GetThreadContext(hT.get(), &ctx))
						{
							debuggerMessage("sw GetThreadContext failed ", GetLastError());
							return;
						}
						ctx.Rip = (SIZE_T)breakAddr;

						if(!SetThreadContext(hT.get(), &ctx))
						{
							debuggerMessage("sw SetThreadContext failed ", GetLastError());
							return;
						}
					}

					if(tempBreakpoint.first != nullptr)
					{
						if(breakpoints.find(tempBreakpoint.first) == breakpoints.end())
							deleteTempBreakpoint();
						tempBreakpoint.first = nullptr;
					}
					if (finishing)
					{
						setTrapFlag();
						ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
					}

					break;
				}
				case EXCEPTION_SINGLE_STEP:
				{
					if(lastBreakpoint != nullptr)
					{
					
						if (breakpoints.find(lastBreakpoint) != breakpoints.end())
						{
							BYTE int3 = 0xcc;
							if (!WriteProcessMemory(hProcess.get(), lastBreakpoint, &int3, sizeof(BYTE), NULL))
								debuggerMessage("EXCEPTION_SINGLE_STEP WriteProcessMemory failed ", GetLastError());
						}
						lastBreakpoint = nullptr;
						if(continueTrap)
						{
							unsetTrapFlag();
							continueTrap = false;
							continueExecution();
							return;
						}
					}
					if (finishing)
					{
						finish();
						while(finishing)
							handleDebugEvent(level+1);
					}
					if (returning)
					{
						SmartHandle hT = getDebugEventsThread();
						CONTEXT ctx = {};
						ctx.ContextFlags = CONTEXT_ALL;

						if (!GetThreadContext(hT.get(), &ctx))
						{
							debuggerMessage("GetThreadContext failed ", GetLastError());
							return;
						}

						PVOID retAddress;
						SIZE_T len;
						if(!ReadProcessMemory(hProcess.get(), (LPCVOID)ctx.Rsp, &retAddress, sizeof(PVOID), &len))
						{
							debuggerMessage("ReadProcessMemory failed ", GetLastError());
							return;
						}
						setBreakPoint(retAddress, true);
						continueExecution();
						returning = false;
					}
					return;
				}
			}
			
			break;
		}
		
		case CREATE_THREAD_DEBUG_EVENT:
		{
			createThreadEvent();
			continueIfState(busy);
			break;
		}

		case CREATE_PROCESS_DEBUG_EVENT:
		{
			createProcessEvent();
			ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
			ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
			break;
		}

		case EXIT_THREAD_DEBUG_EVENT:
		{
			exitThreadEvent();
			continueIfState(busy);
			break;
		}

		case EXIT_PROCESS_DEBUG_EVENT:
		{
			exitThreadEvent();
			continueIfState(busy);
			break;
		}

		case LOAD_DLL_DEBUG_EVENT:
		{
			//loadDllEvent();
			ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
			break;
		}

		case UNLOAD_DLL_DEBUG_EVENT:
		{
			unloadDllEvent();
			continueIfState(busy);
			break;
		}

		case OUTPUT_DEBUG_STRING_EVENT:
		{
			outputDebugStringEvent();
			continueIfState(busy);
			break;
		}

		case RIP_EVENT:
		{
			ripEvent();
			continueIfState(busy);
			break;
		}
	}		
}

void DebuggerEngine::showStack(SIZE_T sz)
{
	PVOID stackAddr;
	std::unique_ptr<PVOID[]> stackToView(new PVOID[sz]);
	SmartHandle hT = getDebugEventsThread();
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;

	if (stackToView == nullptr)
		return;

	if(!GetThreadContext(hT.get(), &ctx))
	{
		debuggerMessage("GetThreadContext failed ", GetLastError());
		return;
	}

	stackAddr = (PVOID)ctx.Rsp;

	if(!ReadProcessMemory(hProcess.get(), stackAddr, stackToView.get(), sizeof(PVOID) * sz, NULL))
	{
		debuggerMessage("showstack ReadProcessMemory %l", GetLastError());
		return;
	}

	for(SIZE_T i=0; i<sz; i++)
		debuggerMessage((PVOID)((SIZE_T)stackAddr+sizeof(SIZE_T)*i), "\t", stackToView[i]);
}

void DebuggerEngine::exit()
{
	std::exit(0);
}

void DebuggerEngine::showGeneralPurposeRegisters()
{
	SmartHandle hT = getDebugEventsThread();
	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_ALL;

	if(!GetThreadContext(hT.get(), &ctx))
	{
		debuggerMessage("GetThreadContext failed ", GetLastError());
		return;
	}
	debuggerMessage("Rax=", (PVOID)ctx.Rax); 
	debuggerMessage("Rbx=", (PVOID)ctx.Rbx); 
	debuggerMessage("Rcx=", (PVOID)ctx.Rcx); 
	debuggerMessage("Rdx=", (PVOID)ctx.Rdx); 
	debuggerMessage("Rbx=", (PVOID)ctx.Rbx); 
	debuggerMessage("Rsp=", (PVOID)ctx.Rsp); 
	debuggerMessage("Rbp=", (PVOID)ctx.Rbp); 
	debuggerMessage("Rsi=", (PVOID)ctx.Rsi); 
	debuggerMessage("Rdi=", (PVOID)ctx.Rdi); 
	debuggerMessage("Rip=", (PVOID)ctx.Rip);
}

void DebuggerEngine::disassembly(PVOID addr, SIZE_T sz)
{
	std::unique_ptr<BYTE[]> buf(new BYTE[sz]);
	if (buf == nullptr)
		return;
	if (!ReadProcessMemory(hProcess.get(), addr, buf.get(), sz, &sz))
	{
		std::stringstream ss;
		ss << addr << "\n";
		std::cerr << "Cannot access memory at address " + ss.str();
	}
	replaceInt3(addr, buf.get(), sz);

	size_t imageEnd = reinterpret_cast<size_t>(imageBase) + ntHdr.OptionalHeader.SizeOfImage;
	std::pair<std::string, Dwarf_Unsigned> funcInfo;
	size_t functionStart = 0;
	size_t funcOffset = 0;
	if (addr >= imageBase && addr < reinterpret_cast<PVOID>(imageEnd))
	{
		funcOffset = reinterpret_cast<size_t>(addr) - reinterpret_cast<size_t>(imageBase);
		funcInfo = matchFunctionSymbol(funcOffset, functionStart);
	}

	// visualize relative addressing
	ZyanU64 runtime_address = (ZyanU64)addr;
	ZyanUSize offset = 0;
	ZydisDisassembledInstruction instruction;
	size_t lastFuncOffset = 0;
	bool f = false;
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(
		 ZYDIS_MACHINE_MODE_LONG_64,
		runtime_address,
		buf.get() + offset,
		sz - offset,
		&instruction
	))) {
		if (funcInfo.second)
		{
			size_t curInsOff = lastFuncOffset;
			if(!f)
				curInsOff = reinterpret_cast<size_t>(addr) - (reinterpret_cast<size_t>(imageBase) + functionStart) + lastFuncOffset;
			printf("%016" PRIX64 " %s+%x %s\n", runtime_address, funcInfo.first.c_str(), curInsOff, instruction.text);
		}
		else
		{
			funcOffset = runtime_address - reinterpret_cast<size_t>(imageBase);
			funcInfo = matchFunctionSymbol(funcOffset, functionStart);
			if (funcInfo.second)
			{
				lastFuncOffset = 0;
				f = true;
				printf("%016" PRIX64 " %s+%x %s\n", runtime_address, funcInfo.first.c_str(), lastFuncOffset, instruction.text);
			}
			else
				printf("%016" PRIX64 "  %s\n", runtime_address, instruction.text);
		}
		offset += instruction.info.length;
		lastFuncOffset = offset;
		if(funcInfo.second < instruction.info.length)
			funcInfo.second = 0;
		else
			funcInfo.second -= instruction.info.length;
		runtime_address += instruction.info.length;
	}
}




void DebuggerEngine::stepOver()
{
	EXCEPTION_RECORD* exceptionRecord = &debugEvent.u.Exception.ExceptionRecord;
	PVOID addr = exceptionRecord->ExceptionAddress;
	ZyanU64 runtime_address = (ZyanU64)addr;
	ZyanUSize offset = 0;
	ZydisDisassembledInstruction instruction;

	BYTE buf[30];
	if (!ReadProcessMemory(hProcess.get(), addr, buf, 30, NULL))
	{
		debuggerMessage("singleStep ReadProcessMemory failed ", GetLastError());
		return;
	}

	if (!ZYAN_SUCCESS(ZydisDisassembleIntel(
		ZYDIS_MACHINE_MODE_LONG_64,
		runtime_address,
		buf,
		30,
		&instruction
	)))
		return;

	if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
	{
		PVOID bpBuf = reinterpret_cast<PVOID>(reinterpret_cast<size_t>(addr) + static_cast<size_t>(instruction.info.length));
		setBreakPoint(bpBuf, true);
		continueExecution();
		return;
	}
	setTrapFlag();
	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
}

void DebuggerEngine::finish()
{
	EXCEPTION_RECORD* exceptionRecord = &debugEvent.u.Exception.ExceptionRecord;
	PVOID addr = exceptionRecord->ExceptionAddress;
	ZyanU64 runtime_address = (ZyanU64)addr;
	ZydisDisassembledInstruction instruction;

	finishing = true;
	BYTE buf[30];
	if (!ReadProcessMemory(hProcess.get(), addr, buf, 30, NULL))
	{
		debuggerMessage("singleStep ReadProcessMemory failed ", GetLastError());
		return;
	}

	if (!ZYAN_SUCCESS(ZydisDisassembleIntel(
		ZYDIS_MACHINE_MODE_LONG_64,
		runtime_address,
		buf,
		30,
		&instruction
	)))
		return;

	if (instruction.info.mnemonic == ZYDIS_MNEMONIC_RET)
	{
		finishing = false;
		returning = true;
		return;
	}
	else if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
	{

		PVOID bpBuf = reinterpret_cast<PVOID>(reinterpret_cast<size_t>(addr) + static_cast<size_t>(instruction.info.length));
		setBreakPoint(bpBuf, true);
		continueExecution();
		return;
	}
	setTrapFlag();
	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
}

void DebuggerEngine::stepIn()
{
	setTrapFlag();
	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
}

void DebuggerEngine::deleteTempBreakpoint()
{
	if (!WriteProcessMemory(hProcess.get(), tempBreakpoint.first, &tempBreakpoint.second, sizeof(BYTE), NULL))
	{
		debuggerMessage("deleteTempBreakpoint WriteProcessMemory failed ", GetLastError());
		return;
	}
}

void DebuggerEngine::setBreakPoint(PVOID breakAddr, bool temp)
{
	BYTE buf, int3;
	MEMORY_BASIC_INFORMATION memInfo;
	memset(&memInfo, 0, sizeof(MEMORY_BASIC_INFORMATION));

	if(breakpoints.find(breakAddr) != breakpoints.end())
	{
		debuggerMessage("Breakpoint was alread set on given address");
		return;
	}

	if(!VirtualQueryEx(hProcess.get(), breakAddr, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		debuggerMessage("setBreakPoint VirtualQueryEx failed ", GetLastError());
		return;
	}

	if(memInfo.State != MEM_COMMIT)
	{
		debuggerMessage("Cannot set breakpoint. Memory address is not committed");
		return;
	}

	if(!ReadProcessMemory(hProcess.get(), breakAddr, &buf, sizeof(BYTE), NULL))
	{
		debuggerMessage("setBreakPoint ReadProcessMemory failed ", GetLastError());
		return;
	}

	if(temp)
		tempBreakpoint = std::make_pair(breakAddr, buf);
	else
		breakpoints[breakAddr] = buf;

	int3 = 0xcc;

	if(!WriteProcessMemory(hProcess.get(), breakAddr, &int3, sizeof(BYTE), NULL))
	{
		debuggerMessage("WriteProcessMemory ReadProcessMemory failed ", GetLastError());
		return;
	}
}


void DebuggerEngine::continueExecution()
{
	if(lastBreakpoint != nullptr)
	{
		setTrapFlag();
		continueTrap = true;
	}
	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	state = busy;
}


//TODO: implement changing directory when restarting debuggee
void DebuggerEngine::restart()
{
	if(isAttached)
	{
		debuggerMessage("Cannot restart debuggee. Process wasnt created in debugger context(it was attached)");
		return;
	}

	std::unique_ptr <RTL_USER_PROCESS_PARAMETERS> procParams = loadProcessParameters();
	if(procParams == nullptr)
		return;

	UnicodeStringEx cmd(hProcess.get(), &procParams->CommandLine);
	TerminateProcess(hProcess.get(), 33);
	WaitForSingleObject(hProcess.get(), 100);

	hProcess = startup(cmd.realUnicode.Buffer);
	state = halt;
	firstBreakpoint = true;
	lastBreakpoint = nullptr;
}

void DebuggerEngine::breakSignal()
{
	DebugBreakProcess(hProcess.get());
}

void DebuggerEngine::threadsInfo()
{
	for(auto &idHandle : listActiveThreads())
		debuggerMessage("Thread - ", idHandle.first);
}

void DebuggerEngine::memoryMappingInfo()
{
	/*
	print process memory map page by page
	it adds info if page is module, stack, heap, peb, teb
	but it doesnt work correctly if memory region contain more than 1 of those
	e.g if memory region contains peb, and tebs structures function will print only "peb"
	*/
	SIZE_T startAddr = 0;
	MEMORY_BASIC_INFORMATION memInfo;
	memset(&memInfo, 0, sizeof(MEMORY_BASIC_INFORMATION));
	std::map<PVOID, std::string> memoryDescription = sketchMemory();

	while (VirtualQueryEx(hProcess.get(), (LPCVOID)startAddr, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		std::stringstream descStream;
		descStream << asHex(memInfo.BaseAddress) << "\t" << std::setw(16) << asHex(memInfo.RegionSize) << "\t" << memStateAsString(memInfo.State) << "\t" << memTypeAsString(memInfo.Type);
		if(memoryDescription.find(memInfo.BaseAddress) != memoryDescription.end())
			descStream << "\t" << memoryDescription[memInfo.BaseAddress];
		debuggerMessage(descStream.str());
		startAddr += memInfo.RegionSize;
	}
}

std::map<PVOID, std::string> DebuggerEngine::sketchMemory()
{
	LIST_ENTRY buf, end;
	std::map<PVOID, std::string> memorySketch;
	std::map<PVOID, std::string> threadsMem;
	SIZE_T pebAddr;

	// obtaining addresses of loaded modules;
	std::unique_ptr<PEB> peb = loadPeb(&pebAddr);
	if (peb == nullptr)
		throw std::runtime_error("Cannot sketch process memory\n");

	std::unique_ptr<PVOID[]> heaps(new PVOID[peb->NumberOfHeaps]);
	if (heaps == nullptr)
		throw std::runtime_error("Cannot sketch process memory\n");

	std::unique_ptr<PEB_LDR_DATA> loaderData = loadLoaderData();
	if(loaderData == nullptr)
		throw std::runtime_error("Cannot sketch process memory\n");

	memorySketch[imageBase]  = "Image base ";
	memorySketch[(PVOID)pebAddr]  = "Peb";
	buf = loaderData->InLoadOrderModuleList;
	if(!ReadProcessMemory(hProcess.get(), loaderData->InLoadOrderModuleList.Flink, &end, sizeof(LIST_ENTRY), NULL))
	{
		debuggerMessage("LIST_ENTRY1 ReadProcessMemory failed ", GetLastError());
		throw std::runtime_error("Cannot sketch process memory\n");
	}

	do
	{
		LDR_MODULE moduleInfo;
		PVOID moduleInfoAddress = CONTAINING_RECORD(buf.Flink, LDR_MODULE, InLoadOrderModuleList);
		if(!ReadProcessMemory(hProcess.get(), moduleInfoAddress, &moduleInfo, sizeof(LDR_MODULE), NULL))
		{
			debuggerMessage("LDR_MODULE ReadProcessMemory failed ", GetLastError());
			throw std::runtime_error("Cannot sketch process memory\n");
		}
		UnicodeStringEx fullModuleName(hProcess.get(), &moduleInfo.FullDllName);

		if(moduleInfo.BaseAddress == peb->ImageBaseAddress) 
			memorySketch[moduleInfo.BaseAddress] += fullModuleName.toString();
		else
			memorySketch[moduleInfo.BaseAddress] = fullModuleName.toString();

		if(!ReadProcessMemory(hProcess.get(), buf.Flink, &buf, sizeof(LIST_ENTRY), NULL))
		{
			debuggerMessage("LIST_ENTRY2 ReadProcessMemory failed ", GetLastError());
			throw std::runtime_error("Cannot sketch process memory\n");
		}
	}while(buf.Flink!=end.Blink);

	// obtaining addresses of heaps

	if (!ReadProcessMemory(hProcess.get(), peb->ProcessHeaps, heaps.get(), peb->NumberOfHeaps * sizeof(PVOID), NULL))
	{
		debuggerMessage("heap ReadProcessMemory failed ", GetLastError());
		throw std::runtime_error("Cannot sketch process memory\n");
	}

	for(ULONG i=0; i<peb->NumberOfHeaps; i++)
		memorySketch[heaps[i]] = "Heap";

	// obtaining threads info (teb, stack)

	threadsMem = sketchThreadMemory();
	memorySketch.insert(threadsMem.begin(), threadsMem.end());
	return memorySketch;
}

std::map<PVOID, std::string> DebuggerEngine::sketchThreadMemory()
{
	std::map<PVOID, std::string> threadMemorySketch;
	NtQueryInformationThread queryThreadInfo = getNtQueryInformationThread();
	if(queryThreadInfo == nullptr)
	{
		debuggerMessage("getNtQueryInformationThread failed ", asHex(GetLastError()));
		return threadMemorySketch;
	}

	for(auto &idHandle : listActiveThreads())
	{
		TEB teb;
		THREAD_BASIC_INFORMATION threadBasicInfo;
		ULONG ret;
		NTSTATUS status = queryThreadInfo(idHandle.second.get(), ThreadBasicInformation, &threadBasicInfo, sizeof(THREAD_BASIC_INFORMATION), &ret);
		if(!NT_SUCCESS(status))
		{
			debuggerMessage("queryThreadInfo failed ", asHex(status));
			continue;
		}
		threadMemorySketch[threadBasicInfo.TebBaseAddress] = std::string("Teb ")+std::to_string(idHandle.first); //TODO: add thread id to memory description;

		if(!ReadProcessMemory(hProcess.get(), threadBasicInfo.TebBaseAddress, &teb, sizeof(TEB), NULL))
		{
			debuggerMessage("ReadProcessMemory TEB ReadProcessMemory failed ", GetLastError());
			continue;
		}

		threadMemorySketch[teb.Tib.StackLimit] = std::string("Stack ")+std::to_string(idHandle.first);
	}
	return threadMemorySketch;
}

std::map<PVOID, std::string> DebuggerEngine::sketchModulesSections(PVOID base, std::string fullModuleName)
{
	std::map<PVOID, std::string> sectionsSkecth;
	IMAGE_DOS_HEADER dosHeader = {};
	IMAGE_NT_HEADERS ntHeaders = {};
	if(!ReadProcessMemory(hProcess.get(), base, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL))
	{
		debuggerMessage("ReadProcessMemory dosHeader ReadProcessMemory failed ", GetLastError());
		return sectionsSkecth;
	}	

	if(!ReadProcessMemory(hProcess.get(), (PVOID)((SIZE_T)base+dosHeader.e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS), NULL))
	{
		debuggerMessage("ReadProcessMemory ntHeaders ReadProcessMemory failed ", GetLastError());
		return sectionsSkecth;
	}

	std::unique_ptr<IMAGE_SECTION_HEADER[]> sectionsHeaders(new IMAGE_SECTION_HEADER[ntHeaders.FileHeader.NumberOfSections]);
	if(sectionsHeaders == nullptr)
		return sectionsSkecth;

	PVOID sectionsHeadersStart = (PVOID)((SIZE_T)base+dosHeader.e_lfanew+sizeof(IMAGE_NT_HEADERS));
	debuggerMessage("sectionsHeadersStart", sectionsHeadersStart);
	if(!ReadProcessMemory(hProcess.get(), sectionsHeadersStart, sectionsHeaders.get(),
			sizeof(IMAGE_SECTION_HEADER)*ntHeaders.FileHeader.NumberOfSections, NULL))
	{
		debuggerMessage("ReadProcessMemory sectionsHeaders ReadProcessMemory failed ", GetLastError());
		return sectionsSkecth;
	}

	for(int i=0; i<ntHeaders.FileHeader.NumberOfSections; i++)
	{
		debuggerMessage((PVOID)((SIZE_T)base+sectionsHeaders[i].VirtualAddress), " - ",
			asHex(sectionsHeaders[i].Misc.VirtualSize)," - ", sectionsHeaders[i].Name);
		sectionsSkecth[(PVOID)((SIZE_T)base+sectionsHeaders[i].VirtualAddress)] = fullModuleName;
	}

	return sectionsSkecth;
}

void DebuggerEngine::sketchMemoryTest()
{
	std::map<PVOID, std::string> mem = sketchMemory();
	for(auto i : mem)
		debuggerMessage(i.first, " - ", i.second);
}

void DebuggerEngine::exceptionEvent()
{
	if (finishing)
		return;
	EXCEPTION_RECORD *exceptionRecord = &debugEvent.u.Exception.ExceptionRecord;
	PVOID addr = exceptionRecord->ExceptionAddress;
	state = halt;

	if(breakpoints.find(addr) != breakpoints.end())
	{
		if(WriteProcessMemory(hProcess.get(), addr, &breakpoints[addr], sizeof(BYTE), NULL))
			lastBreakpoint = addr;
		else
			debuggerMessage("exceptionEvent WriteProcessMemory failed ", GetLastError());
	}
	debuggerMessage("Exception ", 
		asHex(exceptionRecord->ExceptionCode),
		" at address ", 
		exceptionRecord->ExceptionAddress);
}
void DebuggerEngine::createThreadEvent()
{
	debuggerMessage("New thread with id ", debugEvent.dwThreadId);
}

void DebuggerEngine::createProcessEvent()
{
	debuggerMessage("Create Process Event with id ", debugEvent.dwProcessId);
}

void DebuggerEngine::exitThreadEvent()
{
	debuggerMessage("Exiting thread ",  debugEvent.dwThreadId," with code ", debugEvent.u.ExitThread.dwExitCode);
}

void DebuggerEngine::exitProcessEvent()
{
	debuggerMessage("Exiting process with code ", debugEvent.u.ExitProcess.dwExitCode);
}

void DebuggerEngine::loadDllEvent()
{
	if(!isAttached)
	{
		debuggerMessage("loadDllEvent: TODO");
	}
}

void DebuggerEngine::unloadDllEvent()
{
	debuggerMessage("unloadDllEvent");
}

void DebuggerEngine::outputDebugStringEvent()
{
	debuggerMessage("outputDebugString\n");
}

void DebuggerEngine::ripEvent()
{
	debuggerMessage("RIP error number ", debugEvent.u.RipInfo.dwError);
}

void DebuggerEngine::continueIfState(states condition)
{
	if(state == condition)
	{
		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
		state = busy;
	}
}

SmartHandle DebuggerEngine::startup(const wchar_t *cmdLine)
{
    STARTUPINFOW si;
	PROCESS_INFORMATION procInfo;
    bool creationResult;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));

    creationResult = CreateProcessW
    (
        NULL,   // the path
		(LPWSTR)cmdLine,                // Command line
        NULL,                   // Process handle not inheritable
        NULL,                   // Thread handle not inheritable
        FALSE,                  // Set handle inheritance to FALSE
        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory
        &si,            // Pointer to STARTUPINFO structure
        &procInfo           // Pointer to PROCESS_INFORMATION structure
        );
    if(!creationResult)
    	debuggerMessage("CreateProcessW failed ", GetLastError());

	processId = procInfo.dwProcessId;
	CloseHandle(procInfo.hThread);
    return SmartHandle(procInfo.hProcess);
}

NtQueryInformationProcess DebuggerEngine::getNtQueryInformationProcess()
{
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if(hNtdll == NULL)
		return nullptr;

	NtQueryInformationProcess func = (NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	return func;
}

NtQueryInformationThread DebuggerEngine::getNtQueryInformationThread()
{
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if(hNtdll == NULL)
		return nullptr;

	NtQueryInformationThread func = (NtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
	return func;
}

std::unique_ptr<PEB> DebuggerEngine::loadPeb(SIZE_T *addr)
{
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION procInfo;
	ULONG ret;
	NtQueryInformationProcess queryInfoProc = getNtQueryInformationProcess();
	if (queryInfoProc == nullptr)
		return nullptr;

	std::unique_ptr<PEB> peb(new PEB);
	if (peb == nullptr)
	{
		debuggerMessage("failed to allocate memory for peb");
		return nullptr;
	}

	status = queryInfoProc(hProcess.get(), ProcessBasicInformation, &procInfo, sizeof(PROCESS_BASIC_INFORMATION), &ret);
	if(!NT_SUCCESS(status))
	{
		debuggerMessage("NtQueryInformationProcess failed ", GetLastError());
		return nullptr;
	}

	if(addr != nullptr)
		*addr = (SIZE_T)procInfo.PebBaseAddress;

	if(!ReadProcessMemory(hProcess.get(), procInfo.PebBaseAddress, peb.get(), sizeof(PEB), NULL))
	{
		debuggerMessage("loadPeb ReadProcessMemory failed ", GetLastError());
		return nullptr;
	}
	return peb;
}

std::unique_ptr<RTL_USER_PROCESS_PARAMETERS> DebuggerEngine::loadProcessParameters()
{
	std::unique_ptr<RTL_USER_PROCESS_PARAMETERS> procParams(new RTL_USER_PROCESS_PARAMETERS);
	if(procParams == nullptr)
		return nullptr;

	std::unique_ptr<PEB> peb = loadPeb();
	if(peb == nullptr)
		return nullptr;

	if(!ReadProcessMemory(hProcess.get(), peb->ProcessParameters, procParams.get(), sizeof(RTL_USER_PROCESS_PARAMETERS), NULL))
	{
		debuggerMessage("loadProcessParameters ReadProcessMemory failed ", GetLastError());
		return nullptr;
	}
	return procParams;
}

std::unique_ptr<PEB_LDR_DATA> DebuggerEngine::loadLoaderData()
{
	std::unique_ptr <PEB_LDR_DATA> loaderData(new PEB_LDR_DATA);
	if (loaderData == nullptr)
		return nullptr;
	std::unique_ptr<PEB> peb = loadPeb();
	if(peb == nullptr)
		return nullptr;

	if(!ReadProcessMemory(hProcess.get(), peb->LoaderData, loaderData.get(), sizeof(PEB_LDR_DATA), NULL))
	{
		debuggerMessage("loadLoaderData ReadProcessMemory failed ", GetLastError());
		return nullptr;
	}
	return loaderData;
}

std::string DebuggerEngine::memStateAsString(DWORD state)
{
	if(state == MEM_COMMIT)
		return std::string("MEM_COMMIT");	
	else if(state == MEM_FREE)
		return std::string("MEM_FREE");
	else if(state == MEM_RESERVE)
		return std::string("MEM_RESERVE");
	return std::string("NONE STATE");
}

std::string DebuggerEngine::memTypeAsString(DWORD state)
{
	if(state == MEM_IMAGE)
		return std::string("MEM_IMAGE");	
	else if(state == MEM_MAPPED)
		return std::string("MEM_MAPPED");
	else if(state == MEM_PRIVATE)
		return std::string("MEM_PRIVATE");
	return std::string("NONE TYPE");
}

void DebuggerEngine::setTrapFlag()
{
	SmartHandle hT = getDebugEventsThread();
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	
	if(!GetThreadContext(hT.get(), &ctx))
	{
		debuggerMessage("GetThreadContext failed ", GetLastError());
		return;
	}

	ctx.EFlags |= 0x100; // setting trap flag

	if(!SetThreadContext(hT.get(), &ctx))
	{
		debuggerMessage("GetThreadContext failed ", GetLastError());
		return;
	}
}

void DebuggerEngine::unsetTrapFlag()
{
	SmartHandle hT = getDebugEventsThread();
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;

	if(!GetThreadContext(hT.get(), &ctx))
	{
		debuggerMessage("GetThreadContext failed ", GetLastError());
		return;
	}

	ctx.EFlags &= 0xfffffeff; // unsetting trap flag

	if(!SetThreadContext(hT.get(), &ctx))
	{
		debuggerMessage("GetThreadContext failed ", GetLastError());
		return;
	}
}

void DebuggerEngine::breakpointsInfo()
{
	if(breakpoints.empty())
	{
		debuggerMessage("No set breakpoint");
		return;
	}
	for(auto bp : breakpoints)
		debuggerMessage("Breakpoint at ", bp.first);
}

void DebuggerEngine::deleteBreakpoint(PVOID addr)
{
	if(breakpoints.empty())
	{
		debuggerMessage("No set breakpoint");
		return;
	}
	if(breakpoints.find(addr) == breakpoints.end())
	{
		debuggerMessage("No breakpoint at address ", addr);
		return;
	}

	if(!WriteProcessMemory(hProcess.get(), addr, &breakpoints[addr], sizeof(BYTE), NULL))
	{
		debuggerMessage("deleteBreakpoint WriteProcessMemory failed ", GetLastError());
		return;
	}
	breakpoints.erase(addr);
}

void DebuggerEngine::replaceInt3(PVOID addr, BYTE *buf, SIZE_T sz)
{
	for(SIZE_T i=0; i<sz; i++)
	{
		PVOID iAddr = (PVOID)((SIZE_T)addr+i);
		if(breakpoints.find(iAddr) != breakpoints.end())
			buf[i] = breakpoints[iAddr];
	}
}

std::map<DWORD, SmartHandle> DebuggerEngine::listActiveThreads()
{
	std::map<DWORD, SmartHandle> activeThreads;
	SmartHandle hSnap = SmartHandle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId));
	if(!hSnap)
		return activeThreads;
	THREADENTRY32 info;
	info.dwSize = sizeof(THREADENTRY32);
	if (!Thread32First(hSnap.get(), &info))
		throw std::runtime_error("Cannot list active threads");
	do
	{
		if(info.th32OwnerProcessID == processId)
			activeThreads[info.th32ThreadID] = SmartHandle(OpenThread(THREAD_ALL_ACCESS, false, info.th32ThreadID));
	}while(Thread32Next(hSnap.get(), &info));
	return activeThreads;
}

PVOID DebuggerEngine::getImageBase()
{
	std::unique_ptr<PEB> peb = loadPeb();
	if (!peb)
		return nullptr;

	return peb->ImageBaseAddress;
}

std::unique_ptr<char[]> DebuggerEngine::getFullExecPath()
{
	DWORD pathlen = 32767;
	std::unique_ptr<char[]> path(new char[pathlen]);
	if (!path)
		return nullptr;

	if (!QueryFullProcessImageNameA(hProcess.get(), 0, path.get(), &pathlen))
	{
		std::cerr << "GetProcessImageFileNameA failed\n";
		return nullptr;
	}
	std::unique_ptr<char[]> buf(new char[pathlen+1]);
	if (!buf)
		return nullptr;
	memcpy(buf.get(), path.get(), pathlen+1);

	return buf;
}

void DebuggerEngine::loadPeNtHeader()
{
	std::ifstream f(getFullExecPath().get(), std::ios::binary);
	if (!f.is_open())
		return ;

	IMAGE_DOS_HEADER dosHdr;
	f.read(reinterpret_cast<char*>(&dosHdr), sizeof(dosHdr));
	f.seekg(dosHdr.e_lfanew);
	f.read(reinterpret_cast<char*>(&ntHdr), sizeof(ntHdr));
}

void DebuggerEngine::updateLocalVariables(size_t addr)
{
	if (addr >= (size_t)imageBase && addr < (size_t)imageBase + ntHdr.OptionalHeader.SizeOfImage)
	{
		size_t offset = addr - (size_t)imageBase;
		auto it = localVariables.begin();
		localVariables.erase( std::remove_if(localVariables.begin(), localVariables.end(),
				[=](std::shared_ptr<SymbolObject> const& p)
					{ 
						SmartHandle hT = getDebugEventsThread();
						return !(*it)->value(hT.get(), offset); 
					}
			), localVariables.end());

		if (localVariables.empty())
			mapLocalVariables(offset);
	}
	else
		localVariables.clear();
}

std::pair<std::string, Dwarf_Unsigned> DebuggerEngine::matchFunctionSymbol(Dwarf_Unsigned offset, Dwarf_Addr &funcStart)
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
	int res;
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
		res = DW_DLV_ERROR;
		Dwarf_Sig8 signature;
		memset(&signature, 0, sizeof(signature));
		res = dwarf_next_cu_header_e(dbg, 1, &cuDie, &cuHeaderLen,
			&versionStamp, &abbrevOffset, &addrSize, &offsetSize, &extSize,
			&signature, &typeoffset, &nextCuOffset, &headerCuType, &error);

		if (res == DW_DLV_ERROR)
			return false;
		if (res == DW_DLV_NO_ENTRY)
			return false;

		res = findSubprogramInDieChain(cuDie, help, 0);
		help.cuDie = cuDie;
		if (res == FOUND_SUBPROGRAM)
			return true;
		if (res == THIS_CU || res == DW_DLV_ERROR)
			return false;
	}
}

void DebuggerEngine::initDwarf()
{
	char realpath[MAX_PATH];
	Dwarf_Handler errhand = 0;
	Dwarf_Ptr errarg = 0;
	int res = dwarf_init_path(getFullExecPath().get(), realpath, MAX_PATH,
		DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, &error);
	if (res != DW_DLV_OK)
		std::cerr << "No debugging symbols found.\n";
}

void DebuggerEngine::resetDwarf()
{
	if (error)
	{
		if (dbg)
			dwarf_dealloc_error(dbg, error);
	}
	if (dbg)
		dwarf_finish(dbg);

	initDwarf();
}

int DebuggerEngine::findSubprogramInDieChain(Dwarf_Die die, Address2FunctionSymbol& help, int level)
{
	int res = checkDieForSubprogram(die, help, level);
	if (res == DW_DLV_ERROR)
		return res;
	if (res == DW_DLV_NO_ENTRY)
		return res;
	if (res == NOT_THIS_CU)
		return res;
	if (res == FOUND_SUBPROGRAM)
		return res;

	Dwarf_Die iterDie = die;
	Dwarf_Die child;
	for (;;)
	{
		Dwarf_Die sibDie = 0;
		int res = dwarf_child(iterDie, &child, &error);
		if (res == DW_DLV_ERROR)
			return res;
		if (res == DW_DLV_OK)
		{
			int res2 = findSubprogramInDieChain(child, help, level + 1);
			if (res2 == FOUND_SUBPROGRAM ||
				res2 == NOT_THIS_CU ||
				res2 == DW_DLV_ERROR)
				return res2;
			
			child = 0;
		}
		res = dwarf_siblingof_c(iterDie, &sibDie, &error);
		if (res == DW_DLV_ERROR)
			return res;
		if (res == DW_DLV_NO_ENTRY)
			break;
		if (iterDie != die)
			dwarf_dealloc(dbg, iterDie, DW_DLA_DIE);
		iterDie = sibDie;
		res = checkDieForSubprogram(iterDie, help, level);
		if(res == DW_DLV_ERROR || res == FOUND_SUBPROGRAM)
			return res;
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
	else if (tag == DW_TAG_compile_unit ||
		tag == DW_TAG_partial_unit ||
		tag == DW_TAG_type_unit)
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
	lowPc -= ntHdr.OptionalHeader.ImageBase;

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
	lowPc -= ntHdr.OptionalHeader.ImageBase;
	if (help.offset < lowPc || help.offset >= lowPc + highPc)
		return DW_DLV_OK;

	char* name = 0;
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
	int res;

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
	res = dwarf_diename(abrootdie, name, &error);
	dwarf_dealloc_die(abrootdie);
	return !res;
}

int DebuggerEngine::getHighOffset(Dwarf_Die die, Dwarf_Addr *lowpc, Dwarf_Addr *highpc, Dwarf_Error *err)
{
	Dwarf_Addr ret = 0;
	Dwarf_Half form = 0;
	Dwarf_Form_Class formclass = (Dwarf_Form_Class)0;
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
	int res = DW_DLV_ERROR;
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
		res = DW_DLV_ERROR;
		Dwarf_Sig8 signature;
		memset(&signature, 0, sizeof(signature));
		res = dwarf_next_cu_header_e(dbg, 1, &cuDie, &cuHeaderLen,
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
	if (res == DW_DLV_ERROR)
		return res;
	if (res == DW_DLV_NO_ENTRY)
		return res;
	if (res == NOT_THIS_CU)
		return res;
	if (res == FOUND_SUBPROGRAM)
	{
		scanSubprogramForVariables(die, help, 0);
		return res;
	}

	Dwarf_Die iterDie = die;
	Dwarf_Die child;
	for (;;)
	{
		Dwarf_Die sibDie = 0;
		int res = dwarf_child(iterDie, &child, &error);
		if (res == DW_DLV_ERROR)
			return res;
		if (res == DW_DLV_OK)
		{
			int res2 = findVariablesInSubprogram(child, help, level + 1);
			if (res2 == FOUND_SUBPROGRAM ||
				res2 == NOT_THIS_CU ||
				res2 == DW_DLV_ERROR)
				return res2;

			child = 0;
		}
		res = dwarf_siblingof_c(iterDie, &sibDie, &error);
		if (res == DW_DLV_ERROR)
			return res;
		if (res == DW_DLV_NO_ENTRY)
			break;
		if (iterDie != die)
			dwarf_dealloc(dbg, iterDie, DW_DLA_DIE);
		iterDie = sibDie;
		res = checkDieForSubprogram(iterDie, help, level);
		if (res == FOUND_SUBPROGRAM)
		{
			scanSubprogramForVariables(iterDie, help, 0);
			return res;
		}
		else if (res == DW_DLV_ERROR)
			return res;
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
	else if (tag == DW_TAG_compile_unit ||
		tag == DW_TAG_partial_unit ||
		tag == DW_TAG_type_unit)
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
	lowPc -= ntHdr.OptionalHeader.ImageBase;

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
	lowPc -= ntHdr.OptionalHeader.ImageBase;
	if (help.offset < lowPc || help.offset >= lowPc + highPc)
		return DW_DLV_OK;

	help.subprogram = die;

	return FOUND_SUBPROGRAM;
}

int DebuggerEngine::scanSubprogramForVariables(Dwarf_Die die, Address2Locals& help, int level)
{
	extractVariableFromTag(die, help);
	Dwarf_Die child;
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

void DebuggerEngine::extractVariableFromTag(Dwarf_Die die, Address2Locals &help)
{
	Dwarf_Half tag = 0;
	int res = dwarf_tag(die, &tag, &error);
	if (res != DW_DLV_OK)
		return;
	if (tag == DW_TAG_variable || tag == DW_TAG_formal_parameter)
	{
		std::pair<Dwarf_Die, Dwarf_Die> dies = std::make_pair(die, (Dwarf_Die)0);
		Dwarf_Attribute attr = 0;
		res = dwarf_attr(die, DW_AT_abstract_origin, &attr, &error);
		if (res == DW_DLV_OK)
		{
			Dwarf_Off off = 0;
			Dwarf_Bool info = 0;
			res = dwarf_formref(attr, &off, &info, &error);
			if (res == DW_DLV_OK)
			{
				Dwarf_Die abstractDie;
				res = dwarf_offdie_b(dbg, off, info, &abstractDie, &error);
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
				auto sym = std::make_shared<VariableObject>(hProcess.get(), dbg, loclist, count, help.subprogram, error, name.value());
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

int DebuggerEngine::attrWithhAbstractOrigin(std::pair<Dwarf_Die, Dwarf_Die> dies, Dwarf_Half attrNum, Dwarf_Attribute *attr)
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
	char* name = 0;
	int res = dwarf_diename(dies.first, &name, &error);
	if (res == DW_DLV_OK)
		return std::string(name);
	else
	{
		Dwarf_Die abrootdie = 0;
		Dwarf_Attribute ab_attr = 0;
		Dwarf_Off ab_offset = 0;
		int res;
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
			dwarf_dealloc_die(abrootdie);
			return std::string(name);
		}
		dwarf_dealloc_die(abrootdie);
	}
	return std::nullopt;
}


void DebuggerEngine::printLocal(std::string varName)
{
	EXCEPTION_DEBUG_INFO& exception = debugEvent.u.Exception;
	PVOID breakAddr = exception.ExceptionRecord.ExceptionAddress;
	size_t addr = ntHdr.OptionalHeader.ImageBase + (size_t)breakAddr - (size_t)imageBase;
	updateLocalVariables((size_t)breakAddr);
	for (auto x : localVariables)
	{
		if (x->symbolName == varName)
		{
			SmartHandle hT = getDebugEventsThread();
			auto val = x->value(hT.get(), addr);
			if (val)
				std::cout << varName << " = " << val.value() << "\n";
			else
				std::cerr << "Cant retrieve " << varName << " value\n";
		}
	}
}

void DebuggerEngine::showLocals()
{
	for (auto& x : localVariables)
	{
		if (auto v = std::dynamic_pointer_cast<VariableObject>(x))
		{
			std::cout << "varobj: " << v->symbolName << "\n";
		}
		else if (auto v = std::dynamic_pointer_cast<ConstObject>(x))
		{
			std::cout << "constobj: " << v->symbolName << "\n";
		}
	}
}

std::optional<std::string> DebuggerEngine::findCurrentSource(size_t lines)
{
	EXCEPTION_DEBUG_INFO& exception = debugEvent.u.Exception;
	PVOID breakAddr = exception.ExceptionRecord.ExceptionAddress;
	Dwarf_Unsigned off = (Dwarf_Unsigned)breakAddr - (Dwarf_Unsigned)imageBase;
	return findFunctionSource(off, lines);
}

std::optional<std::string> DebuggerEngine::findFunctionSource(Dwarf_Unsigned offset, size_t lines)
{
	Address2FunctionSymbol help(offset);

	if (!findSubprogramInCuChain(help))
		return std::nullopt;

	char** srcs = 0;
	Dwarf_Unsigned version = 0;
	Dwarf_Small tableCount = 0;
	Dwarf_Line_Context context = 0;

	int res = dwarf_srclines_b(help.cuDie, &version, &tableCount, &context, &error);
	if (res != DW_DLV_OK)
		return std::nullopt;

	Dwarf_Line* lineBuf = 0;
	Dwarf_Signed lineCount = 0;
	res = dwarf_srclines_from_linecontext(context,
		&lineBuf, &lineCount, &error);
	if (res != DW_DLV_OK)
		return std::nullopt;

	size_t addressLineNumber;
	Dwarf_Signed idx = findAddressLineIndex(lineBuf, lineCount, &addressLineNumber, help);
	if (idx == -1)
		return std::nullopt;

	lines = lines >= lineCount ? lineCount / 2 : lines/2;

	Dwarf_Signed startIdx = idx >= lines ? idx - lines : 0;
	Dwarf_Signed endIdx = idx >= lineCount-lines-1 ? lineCount-1 : idx+lines;

	char* srcName = 0;
	res = dwarf_linesrc(lineBuf[idx], &srcName, &error);
	if (res != DW_DLV_OK)
		return std::nullopt;
		
	std::pair<size_t, size_t> lineRange;
	res = dwarf_lineno(lineBuf[startIdx], &lineRange.first, &error);
	if (res != DW_DLV_OK)
		return std::nullopt;

	res = dwarf_lineno(lineBuf[endIdx], &lineRange.second, &error);
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
	if (ret.str().size())
		return ret.str();
	return std::nullopt;
}

Dwarf_Signed DebuggerEngine::findAddressLineIndex(Dwarf_Line* lineBuf,
	Dwarf_Signed lineCount, size_t* lineNum, Address2FunctionSymbol &help)
{
	size_t previous = 0;
	Dwarf_Signed ret = -1;
	int res = DW_DLV_ERROR;
	for (Dwarf_Signed i = 0; i < lineCount && ret == -1; i++)
	{
		Dwarf_Addr retAddr = 0;
		res = dwarf_lineaddr(lineBuf[i], &retAddr, &error);
		if (res != DW_DLV_OK)
			continue;

		size_t offset = retAddr - ntHdr.OptionalHeader.ImageBase;

		if (i)
		{
			if (offset == help.offset)
				ret = i;
			else if (help.offset > previous && help.offset < offset)
				ret = i - 1;
		}
		else if (offset == help.offset)
			ret = 0;

		previous = offset;
	}
	if(ret != -1)
		res = dwarf_lineno(lineBuf[ret], lineNum, &error);
	if (res != DW_DLV_OK)
		return -1;
	return ret;
}

std::string DebuggerEngine::correctWslPath(std::string input)
{
	std::string path = input;
	std::string prefix = "/mnt/c";
	if (path.rfind(prefix, 0) == 0) 
	{
		path.replace(0, prefix.size(), "C:\\");
	}

	std::replace(path.begin(), path.end(), '/', '\\');
	return path;
}