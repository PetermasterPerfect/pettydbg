#include "debugger.h"
extern Debugger *dbg;

BOOL WINAPI registerSignals(DWORD dwCtrlType)
{
	if(dwCtrlType == CTRL_C_EVENT)
		goto KILL;
	else if (dwCtrlType == CTRL_BREAK_EVENT)
	{
		if(dbg->state == running)
		{
			dbg->breakSignal();
			goto RET;
		}
		else
			goto KILL;
	}
KILL:
	DebugActiveProcessStop(dbg->procInfo.dwProcessId);
	ExitProcess(0xcc);
RET:
	return TRUE;
}

Debugger::Debugger(wchar_t *cmd)
{
	hProcess = startup(cmd);
	if(hProcess == NULL)
		fprintf(stderr, "startup failed [%lx]\n", GetLastError());

	printf("Running %ls with id %i\n", cmd, GetProcessId(hProcess));
	firstBreakpoint = false;
	state = not_running;
	SetConsoleCtrlHandler(registerSignals, TRUE);
	DebugSetProcessKillOnExit(TRUE);
}

Debugger::Debugger(DWORD pid)
{
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if(hProcess == NULL)
	{
		fprintf(stderr, "OpenProcess failed [%lx]\n", GetLastError());
		return;
	}

	if(!DebugActiveProcess(pid))
	{
		fprintf(stderr, "DebugActiveProcess failed [%lx]\n", GetLastError());
		return;
	}

	printf("Attaching to process with id %i\n", pid);
	processId = pid;
	firstBreakpoint = false;
	state = bpoint;
	SetConsoleCtrlHandler(registerSignals, TRUE);
	DebugSetProcessKillOnExit(TRUE);
}

template<class... Args> void Debugger::debuggerMessage(Args... args)
{
	(std::cout << ... << args) << std::endl;
}


template <typename T> std::string Debugger::asHex(T num)
{
	std::stringstream sstream;
	sstream << std::hex << num;
	return sstream.str();
}


//https://stackoverflow.com/questions/1070497/c-convert-hex-string-to-signed-integer
SIZE_T Debugger::fromHex(std::string str)
{
	SIZE_T x;
	std::stringstream ss;
	ss << std::hex << str;
	ss >> x;
	return x;
}

std::string Debugger::argumentAsHex(std::string arg)
{
	std::string potentialAddr = arg;
	if(potentialAddr.substr(0, 2) == "0x")
		potentialAddr = potentialAddr.substr(2, std::string::npos);

	return potentialAddr;
}

void Debugger::enterDebuggerLoop()
{
	memset(&debugEvent, 0, sizeof(DEBUG_EVENT));
	if(WaitForDebugEvent(&debugEvent, 100) && debugEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
		continueIfAndRun(not_running);

	while(true)
	{
		if(state != running)
		{
			commandLineInterface();
			if(cmdToHandle == true)
				handleCmd();
		}
		if(!WaitForDebugEvent(&debugEvent, 10))
			continue;
		exceptionSwitchedCased();
	}
}

void Debugger::handleCmd() // TODO: almost everything in this function
{
	if(cmdToHandle && arguments.size() >= 1)
	{
		if(arguments[0] == "c")
			continueCommand();
		else if(arguments[0] == "run") // restart
			runCommand();
		else if(arguments[0] == "thinfo")
			enumerateThreadsCommand();
		else if(arguments[0] == "m")
			sketchMemoryTest();	
		else if(arguments[0] == "mem")
			enumerateMemoryPagesCommand();
		// else if(arguments[0] == "systembp")
		// 	setSystemBreakpoint();
		else if(arguments[0] == "n") // single step (no differentiation between step in and step over yet)
			singleStepCommand();
		else if(arguments[0] == "reg")
			showGeneralPurposeRegisters();
		else if(arguments[0] == "stack")
		{
			if(arguments.size() != 2)
				debuggerMessage("Bad syntax!!!");
			else
				showStack(stoi(arguments[1]));
		}
		else if(arguments[0] == "bp") // setting a breakpoint
		{
			if(arguments.size() != 2)
				debuggerMessage("Bad syntax!!!");
			else	
				setBreakPoint((PVOID)fromHex(argumentAsHex(arguments[1])));
		}
		else if(arguments[0] == "dis")
		{
			if(arguments.size() != 3)
				debuggerMessage("Bad syntax!!!");
			else
				dissassembly((PVOID)fromHex(argumentAsHex(arguments[1])), stoi(arguments[2]));
		}
		else
			debuggerMessage("Command isnt recognized");
		arguments.clear();
		cmdToHandle = false;
	}
}

void Debugger::exceptionSwitchedCased()
{
	switch(debugEvent.dwDebugEventCode)
	{
		//TODO: first chance exception
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
						HANDLE hT = activeThreads[debugEvent.dwThreadId];
						CONTEXT ctx;
						ctx.ContextFlags = CONTEXT_CONTROL;

						if(!GetThreadContext(hT, &ctx))
						{
							debuggerMessage("sw GetThreadContext failed ", GetLastError());
							return;
						}
						ctx.Rip = (SIZE_T)breakAddr;

						if(!SetThreadContext(hT, &ctx))
						{
							debuggerMessage("sw SetThreadContext failed ", GetLastError());
							return;
						}
					}

					break;
				}
				case EXCEPTION_SINGLE_STEP:
				{
					if(lastBreakpoint != nullptr)
					{
						BYTE int3 = 0xcc;
						if(!WriteProcessMemory(hProcess, lastBreakpoint, &int3, sizeof(BYTE), NULL))
							debuggerMessage("EXCEPTION_SINGLE_STEP WriteProcessMemory failed ", GetLastError());
						lastBreakpoint = nullptr;
						if(continueTrap)
						{
							unsetTrapFlag();
							continueTrap = false;
							continueCommand();
							return;
						}
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
			continueIfAndRun(running);
			//ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
			break;
		}
		
		case CREATE_PROCESS_DEBUG_EVENT:
		{
			createProcessEvent();
			continueIfAndRun(not_running);
			break;
		}
		
		case EXIT_THREAD_DEBUG_EVENT:
		{
			exitThreadEvent();
			continueIfAndRun(running);
			break;
		}
		
		case EXIT_PROCESS_DEBUG_EVENT:
		{
			exitThreadEvent();
			continueIfAndRun(running);
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
			continueIfAndRun(running);
			break;
		}
		case OUTPUT_DEBUG_STRING_EVENT:
		{
			outputDebugStringEvent();
			continueIfAndRun(running);
			break;
		}
		case RIP_EVENT:
		{
			ripEvent();
			continueIfAndRun(running);
			break;
		}
	}
}

void Debugger::setSystemBreakpoint()
{
	if(state != not_running)
	{
		debuggerMessage("No point in running this command now - sytem breakpoint was alread hit");
		return;
	}

	if(arguments.size() < 2)
	{
		debuggerMessage("Bad command - no argument");
		return;
	}

	if(arguments[1] == "1")
		firstBreakpoint = true;
	else if(arguments[1] == "0")
		firstBreakpoint = false;
	else
		debuggerMessage("Bad argument - expected 1 or 0, given \"", arguments[1], "\"");

}

void Debugger::showStack(SIZE_T sz)
{
	PVOID stackAddr;
	PVOID *stackToView;
	HANDLE hT = activeThreads[debugEvent.dwThreadId];
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;

	if(!GetThreadContext(hT, &ctx))
	{
		debuggerMessage("GetThreadContext failed ", GetLastError());
		return;
	}

	stackAddr = (PVOID)ctx.Rsp;
	stackToView = new PVOID[sz];
	if(stackToView == nullptr)
		return;

	if(!ReadProcessMemory(hProcess, stackAddr, stackToView, sizeof(PVOID)*sz, NULL))
	{
		debuggerMessage("showstack ReadProcessMemory %l", GetLastError());
		delete[] stackToView;
		return;
	}

	for(SIZE_T i=0; i<sz; i++)
		debuggerMessage((PVOID)((SIZE_T)stackAddr+sizeof(SIZE_T)*i), "\t", stackToView[i]);

	delete[] stackToView;
}

void Debugger::showGeneralPurposeRegisters()
{
	HANDLE hT = activeThreads[debugEvent.dwThreadId];
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;

	if(!GetThreadContext(hT, &ctx))
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

void Debugger::dissassembly(PVOID addr, SIZE_T sz)
{

	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return ;

	BYTE *buf = new BYTE[sz];
	if(buf == nullptr)
		return;
	if(!ReadProcessMemory(hProcess, addr, buf, sz, NULL))
	{
		debuggerMessage("dissassembly ReadProcessMemory failed ", GetLastError());
		delete[] buf;
		return;
	}

	count = cs_disasm(handle, (const uint8_t*)buf, sz, (uint64_t)addr, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("%p ", insn[j].address);
			for(int i=0; i<insn[j].size; i++)
				printf("%x", insn[j].bytes[i]);
			printf("\t%s %s\n", insn[j].mnemonic, insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
	delete[] buf;
}

void Debugger::singleStepCommand()
{
	// EXCEPTION_DEBUG_INFO& exception = debugEvent.u.Exception;
	// if(exception.ExceptionRecord.ExceptionCode != STATUS_BREAKPOINT)
	setTrapFlag();
	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
}

void Debugger::setBreakPoint(PVOID breakAddr)
{
	BYTE buf, int3;
	MEMORY_BASIC_INFORMATION memInfo;
	memset(&memInfo, 0, sizeof(MEMORY_BASIC_INFORMATION));

	if(breakpoints.find(breakAddr) != breakpoints.end())
	{
		debuggerMessage("Breakpoint was alread set on given address");
		return;
	}

	if(!VirtualQueryEx(hProcess, breakAddr, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		debuggerMessage("setBreakPoint VirtualQueryEx failed ", GetLastError());
		return;
	}

	if(memInfo.State != MEM_COMMIT)
	{
		debuggerMessage("Cannot set breakpoint. Memory address is not committed");
		return;
	}

	if(!ReadProcessMemory(hProcess, breakAddr, &buf, sizeof(BYTE), NULL))
	{
		debuggerMessage("setBreakPoint ReadProcessMemory failed ", GetLastError());
		return;
	}

	breakpoints[breakAddr] = buf;
	int3 = 0xcc;

	if(!WriteProcessMemory(hProcess, breakAddr, &int3, sizeof(BYTE), NULL))
	{
		debuggerMessage("WriteProcessMemory ReadProcessMemory failed ", GetLastError());
		return;
	}
}


void Debugger::continueCommand()
{
	if(lastBreakpoint != nullptr)
	{
		setTrapFlag();
		continueTrap = true;
	}
	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	state = running;
}


//TODO: implement changing directory when restarting debuggee
void Debugger::runCommand()
{
	if(state == not_running)
	{
		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
		state = running;
	}
	else
	{
		PRTL_USER_PROCESS_PARAMETERS procParams = loadProcessParameters();
		if(procParams == nullptr)
			return;

		UnicodeStringEx cmd(hProcess, &procParams->CommandLine);
		// wchar_t cwdBuf[0x300];
		// UnicodeStringEx cwd(hProcess, &procParams->CurrentDirectoryPath);

		TerminateProcess(hProcess, 33);
		WaitForSingleObject(hProcess, 100);

		activeThreads.clear();
		hProcess = startup(cmd.actualString.Buffer);
		state = not_running;
		firstBreakpoint = true;
		lastBreakpoint = nullptr;
		delete procParams;
	}
}

void Debugger::breakSignal()
{
	DebugBreakProcess(hProcess);
}

void Debugger::enumerateThreadsCommand()
{
	for(auto idHandle : activeThreads)
		debuggerMessage("Thread - ", idHandle.first);
}


void Debugger::enumerateMemoryPagesCommand()
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

	while (VirtualQueryEx(hProcess, (LPCVOID)startAddr, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		std::stringstream descStream;
		descStream << asHex(memInfo.BaseAddress) << "\t" << asHex(memInfo.RegionSize) << "\t" << memStateAsString(memInfo.State) << "\t" << memTypeAsString(memInfo.Type);
		if(memoryDescription.find(memInfo.BaseAddress) != memoryDescription.end())
			descStream << "\t" << memoryDescription[memInfo.BaseAddress];
		debuggerMessage(descStream.str());
		startAddr += memInfo.RegionSize;
	}
}

std::map<PVOID, std::string> Debugger::sketchMemory()
{
	PVOID *heaps;
	LIST_ENTRY buf, end;
	std::map<PVOID, std::string> memorySketch;
	std::map<PVOID, std::string> threadsMem;
	//std::vector<std::map<PVOID, std::string>> sectionsMem;
	SIZE_T pebAddr;

	// obtaining addresses of loaded modules;
	PPEB peb = loadPeb(&pebAddr);
	if(peb == nullptr)
		return memorySketch;

	PPEB_LDR_DATA loaderData = loadLoaderData();
	if(loaderData == nullptr)
	{
		delete peb;
		return memorySketch;
	}

	memorySketch[peb->ImageBaseAddress]  = "Image base ";
	memorySketch[(PVOID)pebAddr]  = "Peb";
	buf = loaderData->InLoadOrderModuleList;
	if(!ReadProcessMemory(hProcess, loaderData->InLoadOrderModuleList.Flink, &end, sizeof(LIST_ENTRY), NULL))
	{
		debuggerMessage("LIST_ENTRY1 ReadProcessMemory failed ", GetLastError());
		goto EXIT;
	}

	do
	{
		LDR_MODULE moduleInfo;
		PVOID moduleInfoAddress = CONTAINING_RECORD(buf.Flink, LDR_MODULE, InLoadOrderModuleList);
		if(!ReadProcessMemory(hProcess, moduleInfoAddress, &moduleInfo, sizeof(LDR_MODULE), NULL))
		{
			debuggerMessage("LDR_MODULE ReadProcessMemory failed ", GetLastError());
			goto EXIT;
		}
		UnicodeStringEx baseModuleName(hProcess, &moduleInfo.BaseDllName);
		UnicodeStringEx fullModuleName(hProcess, &moduleInfo.FullDllName);

		if(moduleInfo.BaseAddress == peb->ImageBaseAddress) 
			memorySketch[moduleInfo.BaseAddress] += fullModuleName.toString();
		else
			memorySketch[moduleInfo.BaseAddress] = fullModuleName.toString();

		//sectionsMem.push_back(sketchModulesSections(moduleInfo.BaseAddress, fullModuleName.toString()));
		//memorySketch.insert(sectionsMem[sectionsMem.size()-1].begin(), sectionsMem[sectionsMem.size()-1].end());

		if(!ReadProcessMemory(hProcess, buf.Flink, &buf, sizeof(LIST_ENTRY), NULL))
		{
			debuggerMessage("LIST_ENTRY2 ReadProcessMemory failed ", GetLastError());
			goto EXIT;
		}
	}while(buf.Flink!=end.Blink);

	// obtaining addresses of heaps

	heaps = new PVOID[peb->NumberOfHeaps];
	if(heaps == nullptr)
		goto EXIT;

	if (!ReadProcessMemory(hProcess, peb->ProcessHeaps, heaps, peb->NumberOfHeaps*sizeof(PVOID), NULL))
	{
		debuggerMessage("heap ReadProcessMemory failed ", GetLastError());
		goto EXIT1;
	}

	for(ULONG i=0; i<peb->NumberOfHeaps; i++)
		memorySketch[heaps[i]] = "Heap";

	// obtaing threads stuff (tebs, stacks)

	threadsMem = sketchThreadMemory();
	memorySketch.insert(threadsMem.begin(), threadsMem.end());

EXIT1:
	delete heaps;
EXIT:
	delete loaderData;
	delete peb;
	return memorySketch;
}

std::map<PVOID, std::string> Debugger::sketchThreadMemory()
{
	debuggerMessage("sketchThreadMemory, current thread ", debugEvent.dwThreadId);
	std::map<PVOID, std::string> threadMemorySketch;
	NtQueryInformationThread queryThreadInfo = getNtQueryInformationThread();
	if(queryThreadInfo == nullptr)
	{
		debuggerMessage("getNtQueryInformationThread failed ", asHex(GetLastError()));
		return threadMemorySketch;
	}


	for(auto idHandle : activeThreads)
	{
		TEB teb;
		THREAD_BASIC_INFORMATION threadBasicInfo;
		ULONG ret;
		NTSTATUS status = queryThreadInfo(idHandle.second, ThreadBasicInformation, &threadBasicInfo, sizeof(THREAD_BASIC_INFORMATION), &ret);
		if(!NT_SUCCESS(status))
		{
			debuggerMessage("queryThreadInfo failed ", asHex(status));
			continue;
		}
		threadMemorySketch[threadBasicInfo.TebBaseAddress] = std::string("Teb ")+std::to_string(idHandle.first); //TODO: add thread id to memory description;

		if(!ReadProcessMemory(hProcess, threadBasicInfo.TebBaseAddress, &teb, sizeof(TEB), NULL))
		{
			debuggerMessage("ReadProcessMemory TEB ReadProcessMemory failed ", GetLastError());
			continue;
		}

		threadMemorySketch[teb.Tib.StackLimit] = std::string("Stack ")+std::to_string(idHandle.first);
	}
	return threadMemorySketch;
}

std::map<PVOID, std::string> Debugger::sketchModulesSections(PVOID base, std::string fullModuleName)
{
	std::map<PVOID, std::string> sectionsSkecth;
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeaders;
	if(!ReadProcessMemory(hProcess, base, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL))
	{
		debuggerMessage("ReadProcessMemory dosHeader ReadProcessMemory failed ", GetLastError());
		return sectionsSkecth;
	}	

	if(!ReadProcessMemory(hProcess, (PVOID)((SIZE_T)base+dosHeader.e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS), NULL))
	{
		debuggerMessage("ReadProcessMemory ntHeaders ReadProcessMemory failed ", GetLastError());
		return sectionsSkecth;
	}

	IMAGE_SECTION_HEADER *sectionsHeaders = new IMAGE_SECTION_HEADER[ntHeaders.FileHeader.NumberOfSections];
	if(sectionsHeaders == nullptr)
		return sectionsSkecth;

	PVOID sectionsHeadersStart = (PVOID)((SIZE_T)base+dosHeader.e_lfanew+sizeof(IMAGE_NT_HEADERS));
	debuggerMessage("sectionsHeadersStart", sectionsHeadersStart);
	if(!ReadProcessMemory(hProcess, sectionsHeadersStart, sectionsHeaders, 
			sizeof(IMAGE_SECTION_HEADER)*ntHeaders.FileHeader.NumberOfSections, NULL))
	{
		debuggerMessage("ReadProcessMemory sectionsHeaders ReadProcessMemory failed ", GetLastError());
		delete sectionsHeaders;
		return sectionsSkecth;
	}

	for(int i=0; i<ntHeaders.FileHeader.NumberOfSections; i++)
	{
		debuggerMessage((PVOID)((SIZE_T)base+sectionsHeaders[i].VirtualAddress), " - ",
			asHex(sectionsHeaders[i].Misc.VirtualSize)," - ", sectionsHeaders[i].Name);
		sectionsSkecth[(PVOID)((SIZE_T)base+sectionsHeaders[i].VirtualAddress)] = fullModuleName;
	}

	delete sectionsHeaders;
	return sectionsSkecth;
}

void Debugger::sketchMemoryTest()
{
	std::map<PVOID, std::string> mem = sketchMemory();
	for(auto i : mem)
		debuggerMessage(i.first, " - ", i.second);
}

void Debugger::exceptionEvent()
{
	EXCEPTION_RECORD *exceptionRecord = &debugEvent.u.Exception.ExceptionRecord;
	PVOID addr = exceptionRecord->ExceptionAddress;
	state = bpoint;

	//if(0)
	if(breakpoints.find(addr) != breakpoints.end())
	{
		if(WriteProcessMemory(hProcess, addr, &breakpoints[addr], sizeof(BYTE), NULL))
			lastBreakpoint = addr;
		else
			debuggerMessage("exceptionEvent WriteProcessMemory failed ", GetLastError());
	}
	debuggerMessage("Exception ", 
		asHex(exceptionRecord->ExceptionCode),
		" at address ", 
		exceptionRecord->ExceptionAddress);
}
void Debugger::createThreadEvent()
{
	activeThreads[debugEvent.dwThreadId] = debugEvent.u.CreateThread.hThread;
	debuggerMessage("New thread with id ", debugEvent.dwThreadId);
}

void Debugger::createProcessEvent()
{
	debuggerMessage("Create Process Event with id ", debugEvent.dwProcessId);
}

void Debugger::exitThreadEvent()
{
	CloseHandle(activeThreads[debugEvent.dwThreadId]);
	activeThreads.erase(debugEvent.dwThreadId);
	debuggerMessage("Exiting thread ",  debugEvent.dwThreadId," with code ", debugEvent.u.ExitThread.dwExitCode);
}

void Debugger::exitProcessEvent()
{
	debuggerMessage("Exiting process with code ", debugEvent.u.ExitProcess.dwExitCode);
}

void Debugger::loadDllEvent()
{
	if(!isAttached)
	{
		debuggerMessage("loadDllEvent: TODO");
	}
}

void Debugger::unloadDllEvent()
{
	debuggerMessage("unloadDllEvent");
}

void Debugger::outputDebugStringEvent()
{
	debuggerMessage("outputDebugString\n");
}

void Debugger::ripEvent()
{
	debuggerMessage("RIP error number ", debugEvent.u.RipInfo.dwError);
}

void Debugger::continueIfAndRun(states cond)
{
	if(state == cond)
	{
		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
		state = running;
	}
}

HANDLE Debugger::startup(const wchar_t *cmdLine)
{
    STARTUPINFOW si;
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
	activeThreads[procInfo.dwThreadId] = procInfo.hThread;//dupHandle(procInfo.hThread);
    return procInfo.hProcess;
}

NtQueryInformationProcess Debugger::getNtQueryInformationProcess()
{
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if(hNtdll == NULL)
		return nullptr;

	NtQueryInformationProcess func = (NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	return func;
}

NtQueryInformationThread Debugger::getNtQueryInformationThread()
{
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if(hNtdll == NULL)
		return nullptr;

	NtQueryInformationThread func = (NtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
	return func;
}

PPEB Debugger::loadPeb(SIZE_T *addr) // loads peb data from debugged process to allocated(heap) buffer so later that memory should be realeased
{
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION procInfo;
	ULONG ret;
	NtQueryInformationProcess queryInfoProc = getNtQueryInformationProcess();
	PPEB peb;
	if(queryInfoProc == nullptr)
		return nullptr;

	status = queryInfoProc(hProcess, ProcessBasicInformation, &procInfo, sizeof(PROCESS_BASIC_INFORMATION), &ret);
	if(!NT_SUCCESS(status))
	{
		debuggerMessage("NtQueryInformationProcess failed ", GetLastError());
		return nullptr;
	}

	peb = new PEB;
	if(peb == nullptr)
	{
		debuggerMessage("failed to allocate memory for peb");
		return nullptr;
	}

	if(addr != nullptr)
		*addr = (SIZE_T)procInfo.PebBaseAddress;

	if(!ReadProcessMemory(hProcess, procInfo.PebBaseAddress, peb, sizeof(PEB), NULL))
	{
		debuggerMessage("loadPeb ReadProcessMemory failed ", GetLastError());
		return nullptr;
	}
	return peb;
}

PRTL_USER_PROCESS_PARAMETERS Debugger::loadProcessParameters()
{
	PRTL_USER_PROCESS_PARAMETERS procParams;
	PPEB peb = loadPeb();
	if(peb == nullptr)
		return nullptr;

	procParams = new RTL_USER_PROCESS_PARAMETERS;
	if(!ReadProcessMemory(hProcess, peb->ProcessParameters, procParams, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL))
	{
		debuggerMessage("loadProcessParameters ReadProcessMemory failed ", GetLastError());
		delete peb;
		return nullptr;
	}

	delete peb;
	return procParams;
}

PPEB_LDR_DATA Debugger::loadLoaderData()
{
	PPEB_LDR_DATA loaderData;
	PPEB peb = loadPeb();
	if(peb == nullptr)
		return nullptr;

	loaderData = new PEB_LDR_DATA;
	if(!ReadProcessMemory(hProcess, peb->LoaderData, loaderData, sizeof(PEB_LDR_DATA), NULL))
	{
		debuggerMessage("loadLoaderData ReadProcessMemory failed ", GetLastError());
		delete peb;
		return nullptr;
	}

	delete peb;
	return loaderData;
}

std::string Debugger::memStateAsString(DWORD state)
{
	if(state == MEM_COMMIT)
		return std::string("MEM_COMMIT");	
	else if(state == MEM_FREE)
		return std::string("MEM_FREE");
	else if(state == MEM_RESERVE)
		return std::string("MEM_RESERVE");
	return std::string("NONE STATE");
}

std::string Debugger::memTypeAsString(DWORD state)
{
	if(state == MEM_IMAGE)
		return std::string("MEM_IMAGE");	
	else if(state == MEM_MAPPED)
		return std::string("MEM_MAPPED");
	else if(state == MEM_PRIVATE)
		return std::string("MEM_PRIVATE");
	return std::string("NONE TYPE");
}

void Debugger::setTrapFlag()
{
	HANDLE hT = activeThreads[debugEvent.dwThreadId];
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;

	
	if(!GetThreadContext(hT, &ctx))
	{
		debuggerMessage("GetThreadContext failed ", GetLastError());
		return;
	}

	ctx.EFlags |= 0x100; // setting trap flag

	if(!SetThreadContext(hT, &ctx))
	{
		debuggerMessage("GetThreadContext failed ", GetLastError());
		return;
	}
	
}

void Debugger::unsetTrapFlag()
{
	HANDLE hT = activeThreads[debugEvent.dwThreadId];
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;

	if(!GetThreadContext(hT, &ctx))
	{
		debuggerMessage("GetThreadContext failed ", GetLastError());
		return;
	}

	ctx.EFlags &= 0xfffffeff; // unsetting trap flag

	if(!SetThreadContext(hT, &ctx))
	{
		debuggerMessage("GetThreadContext failed ", GetLastError());
		return;
	}
}