#include "debugger.h"

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

DebuggerEngine::DebuggerEngine()
{
}

DebuggerEngine::DebuggerEngine(wchar_t *cmd)
{
	hProcess = startup(cmd);
	if(hProcess == NULL)
		fprintf(stderr, "startup failed [%lx]\n", GetLastError());

	printf("Running %ls with id %i\n", cmd, GetProcessId(hProcess.get()));
	isAttached = false;
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


size_t DebuggerEngine::fromHex(std::string str)
{
	size_t x;
	std::stringstream ss;
	ss << std::hex << str;
	ss >> x;
	return x;
}

std::string DebuggerEngine::argumentAsHex(std::string arg)
{
	std::string potentialAddr = arg;
	if(potentialAddr.substr(0, 2) == "0x")
		potentialAddr = potentialAddr.substr(2, std::string::npos);

	return potentialAddr;
}

void DebuggerEngine::handleDebugEvent()
{
	if (!WaitForDebugEvent(&debugEvent, 10))
		return;

	switch(debugEvent.dwDebugEventCode)
	{
		case EXCEPTION_DEBUG_EVENT:
		{
			EXCEPTION_DEBUG_INFO& exception = debugEvent.u.Exception;
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
					PVOID breakAddr = exception.ExceptionRecord.ExceptionAddress;
					if(breakpoints.find(breakAddr) != breakpoints.end())
					{
						SmartHandle hT = std::move(listActiveThreads()[debugEvent.dwThreadId]); // TODO: what if hT is null
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

					if(stepBreakpoint != nullptr)
					{
						deleteBreakpoint(stepBreakpoint);
						stepBreakpoint = nullptr;
					}

					break;
				}
				case EXCEPTION_SINGLE_STEP:
				{
					if(lastBreakpoint != nullptr)
					{
						BYTE int3 = 0xcc;
						if(!WriteProcessMemory(hProcess.get(), lastBreakpoint, &int3, sizeof(BYTE), NULL))
							debuggerMessage("EXCEPTION_SINGLE_STEP WriteProcessMemory failed ", GetLastError());
						lastBreakpoint = nullptr;
						if(continueTrap)
						{
							unsetTrapFlag();
							continueTrap = false;
							continueExecution();
							return;
						}
					}
					if(steppingOut)
					{
						//stepOut();
						return;
					}
					break;
				}
			}
			exceptionEvent();
			break;
		}
		
		case CREATE_THREAD_DEBUG_EVENT:
		{
			createThreadEvent();
			continueIfState(busy);//TODO ???
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
	SmartHandle hT = std::move(listActiveThreads()[debugEvent.dwThreadId]);
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

void DebuggerEngine::showGeneralPurposeRegisters()
{
	SmartHandle hT = std::move(listActiveThreads()[debugEvent.dwThreadId]);
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

void DebuggerEngine::dissassembly(PVOID addr, SIZE_T sz)
{
	std::unique_ptr<BYTE[]> buf(new BYTE[sz]);
	if (buf == nullptr)
		return;
	if (!ReadProcessMemory(hProcess.get(), addr, buf.get(), sz, NULL))
	{
		std::stringstream ss;
		ss << addr << "\n";
		throw std::runtime_error("Cannot access memory at address " + ss.str());
	}
	replaceInt3(addr, buf.get(), sz);

	// visualize relative addressing
	ZyanU64 runtime_address = (ZyanU64)addr;
	ZyanUSize offset = 0;
	ZydisDisassembledInstruction instruction;
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(
		 ZYDIS_MACHINE_MODE_LONG_64,
		runtime_address,
		buf.get() + offset,
		sz - offset,
		&instruction
	))) {
		printf("%016" PRIX64 "  %s\n", runtime_address, instruction.text);
		offset += instruction.info.length;
		runtime_address += instruction.info.length;
	}
}

void DebuggerEngine::stepOver()
{
	EXCEPTION_RECORD* exceptionRecord = &debugEvent.u.Exception.ExceptionRecord;
	PVOID addr = exceptionRecord->ExceptionAddress;
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	BYTE buf[30];
	if (!ReadProcessMemory(hProcess.get(), addr, buf, 30, NULL))
	{
		debuggerMessage("singleStep ReadProcessMemory failed ", GetLastError());
		return;
	}

	ZydisDecodedInstruction instruction;
	ZydisDecoderDecodeInstruction(&decoder, 0, addr, 30,
		&instruction);
	if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL)
	{
		PVOID bpBuf = addr;
		setBreakPoint(bpBuf); // TODO: delete this breakpoint
		stepBreakpoint = bpBuf;
		continueExecution();
	}
	setTrapFlag();
	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
}

/*
void DebuggerEngine::stepOut()
{
	EXCEPTION_RECORD *exceptionRecord = &debugEvent.u.Exception.ExceptionRecord;
	PVOID addr = exceptionRecord->ExceptionAddress;
	csh handle;
	cs_insn *insn;
	size_t count;
	BYTE buf[30]; // x86(x64) opcode is at most 15 bytes long

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return ;

	if(!ReadProcessMemory(hProcess.get(), addr, buf, 30, NULL))
	{
		debuggerMessage("singleStep ReadProcessMemory failed ", GetLastError());
		return;
	}

	steppingOut = true;
	count = cs_disasm(handle, (const uint8_t*)buf, 30, (uint64_t)addr, 0, &insn);
	if (count > 0)
	{
		if(!strcmp(insn[0].mnemonic, "ret"))
		{
			cs_free(insn, count);
			steppingOut = false;
			setTrapFlag();
			ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
			return;
		}
		else if(!strcmp(insn[0].mnemonic, "call"))
		{
			PVOID bpBuf = (PVOID)insn[1].address;
			setBreakPoint(bpBuf);
			stepBreakpoint = bpBuf;
			continueExecution();
			cs_free(insn, count);
			return;
		}
		cs_free(insn, count);
	}
	else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
	setTrapFlag();
	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
}
*/
void DebuggerEngine::stepIn()
{
	setTrapFlag();
	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
}

void DebuggerEngine::setBreakPoint(PVOID breakAddr)
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
// but why??
void DebuggerEngine::restart()
{
	if(isAttached)
	{
		debuggerMessage("Cannot restart debuggee. Process wasnt created in debugger context(it was attached)");
		return;
	}

	if(state == halt)
	{
		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
		state = busy;
	}
	else
	{
		std::unique_ptr <RTL_USER_PROCESS_PARAMETERS> procParams = loadProcessParameters();
		if(procParams == nullptr)
			return;

		UnicodeStringEx cmd(hProcess.get(), &procParams->CommandLine);
		// wchar_t cwdBuf[0x300];
		// UnicodeStringEx cwd(hProcess.get(), &procParams->CurrentDirectoryPath);

		TerminateProcess(hProcess.get(), 33);
		WaitForSingleObject(hProcess.get(), 100);

		hProcess = startup(cmd.realUnicode.Buffer);
		state = halt;
		firstBreakpoint = true;
		lastBreakpoint = nullptr;
	}
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

	memorySketch[peb->ImageBaseAddress]  = "Image base ";
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
	SmartHandle hT = std::move(listActiveThreads()[debugEvent.dwThreadId]);
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
	SmartHandle hT = std::move(listActiveThreads()[debugEvent.dwThreadId]);
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
		debuggerMessage("Not breakpoint at address ", addr);
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