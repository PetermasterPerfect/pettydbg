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
	firstBreakpoint = true;
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

	printf("Attaching to process with id %l\n", pid);
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

void Debugger::enterDebuggerLoop()
{
	memset(&debugEvent, 0, sizeof(DEBUG_EVENT));
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


void Debugger::handleCmd() // TODO: almost everything in this fucntion
{
	if(cmdToHandle && arguments.size() >= 1)
	{
		if(arguments[0] == "run")
			runCommand();
		else if(arguments[0] == "c")
			continueCommand();
		else if(arguments[0] == "thinfo")
			enumerateThreadsCommand();		
		else if(arguments[0] == "mem")
			sketchMemoryTest();
		else
			debuggerMessage("Command isnt recognized");
		arguments.clear();
		cmdToHandle = false;
	}
}

void Debugger::exceptionSwitchedCased()
{
	if(state == not_running)
		return;
	
	switch(debugEvent.dwDebugEventCode)
	{
		//TODO: first chance exception
		case EXCEPTION_DEBUG_EVENT:
		{
			exceptionEvent();
			EXCEPTION_DEBUG_INFO& exception = debugEvent.u.Exception;
			switch( exception.ExceptionRecord.ExceptionCode)
			{
				case STATUS_BREAKPOINT:
				{
					if(firstBreakpoint)
					{
						firstBreakpoint = false;
						if(!ContinueDebugEvent(debugEvent.dwProcessId, 
						debugEvent.dwThreadId, DBG_CONTINUE))
							debuggerMessage("ContinueDebugEvent failed ", GetLastError());
						state 	= running;
					}
					break;
				}
				default:
				{
					debuggerMessage("(default)breakpoint, thread id ", debugEvent.dwThreadId);
				}
			}
			break;
		}
		
		case CREATE_THREAD_DEBUG_EVENT:
		{
			createThreadEvent();
			ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
			break;
		}
		
		case CREATE_PROCESS_DEBUG_EVENT:
		{
			createProcessEvent();
			ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
			break;
		}
		
		case EXIT_THREAD_DEBUG_EVENT:
		{
			exitThreadEvent();
			ContinueDebugEvent(debugEvent.dwProcessId, 
				debugEvent.dwThreadId,
				DBG_CONTINUE);
			break;
		}
		
		case EXIT_PROCESS_DEBUG_EVENT:
		{
			exitThreadEvent();
			ContinueDebugEvent(debugEvent.dwProcessId, 
				debugEvent.dwThreadId,
				DBG_CONTINUE);
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
			ContinueDebugEvent(debugEvent.dwProcessId, 
				debugEvent.dwThreadId,
				DBG_CONTINUE);
			break;
		}
		case OUTPUT_DEBUG_STRING_EVENT:
		{
			outputDebugStringEvent();
			ContinueDebugEvent(debugEvent.dwProcessId, 
				debugEvent.dwThreadId,
				DBG_CONTINUE);
			break;
		}
		case RIP_EVENT:
		{
			ripEvent();
			ContinueDebugEvent(debugEvent.dwProcessId, 
				debugEvent.dwThreadId,
				DBG_CONTINUE);
			break;
		}			
		default:
		{
			//printf("default %x, %x:\n", debugEvent.dwDebugEventCode, debugEvent.u.Exception.ExceptionRecord.ExceptionCode);
		}
	}
}

void Debugger::continueCommand()
{
	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	state = running;
}


//TODO: implement changing directory when restarting
void Debugger::runCommand()
{
	if(state == not_running)
	{
		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
		state = running;
	}
	else
	{
		wchar_t cwdBuf[0x300];
		PRTL_USER_PROCESS_PARAMETERS procParams = loadProcessParameters();
		if(procParams == nullptr)
			return;

		UnicodeStringEx cmd(hProcess, &procParams->CommandLine);
		UnicodeStringEx cwd(hProcess, &procParams->CurrentDirectoryPath);

		TerminateProcess(hProcess, 33);
		WaitForSingleObject(hProcess, 100);

		hProcess = startup(cmd.actualString.Buffer);
		state = not_running;
		firstBreakpoint = true;
		delete procParams;
	}
}

void Debugger::breakSignal()
{
	DebugBreakProcess(hProcess);
}

void Debugger::enumerateThreadsCommand()
{
	THREADENTRY32 threadInfo;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
	if(hSnapshot == INVALID_HANDLE_VALUE)
	{
		debuggerMessage("CreateToolhelp32Snapshot failed ", asHex(GetLastError()));
		return;
	}
	threadInfo.dwSize = sizeof(THREADENTRY32);
	if(!Thread32First(hSnapshot, &threadInfo))
	{
		debuggerMessage("Thread32First failed ", asHex(GetLastError()));
		return;
	}
	do
	{
		if(threadInfo.th32OwnerProcessID == processId)
			debuggerMessage("Thread with id ", threadInfo.th32ThreadID);
		
	}while(Thread32Next(hSnapshot, &threadInfo));
}


void Debugger::enumerateMemoryPagesCommand()
{
	SIZE_T startAddr = 0;
	MEMORY_BASIC_INFORMATION memInfo;
	memset(&memInfo, 0, sizeof(MEMORY_BASIC_INFORMATION));
	std::map<PVOID, std::string> addressesDescription = sketchMemory();

	while (VirtualQueryEx(hProcess, (LPCVOID)startAddr, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{

		startAddr += memInfo.RegionSize;
	}
}

std::map<PVOID, std::string> Debugger::sketchMemory()
{
	PVOID *heaps;
	LIST_ENTRY buf, end;
	std::map<PVOID, std::string> memorySketch;
	std::map<PVOID, std::string> threadsMem;

	// obtaining addresses of loaded modules;
	PPEB peb = loadPeb();
	if(peb == nullptr)
		return memorySketch;

	PPEB_LDR_DATA loaderData = loadLoaderData();
	if(loaderData == nullptr)
	{
		delete peb;
		return memorySketch;
	}

	memorySketch[peb->ImageBaseAddress]  = "Image base ";
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

		if(moduleInfo.BaseAddress == peb->ImageBaseAddress) 
			memorySketch[moduleInfo.BaseAddress] += baseModuleName.toString();
		else
			memorySketch[moduleInfo.BaseAddress] = baseModuleName.toString();

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

	// obtaing threads information related pages (tebs, stacks)

	threadsMem = sketchThreadMemory();
	for(auto i : threadsMem)
		debuggerMessage(i.first, " - ", i.second);
	//memorySketch.insert(threadsMem.begin(), threadsMem.end());

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
	THREADENTRY32 threadInfo;
	NtQueryInformationThread queryThreadInfo = getNtQueryInformationThread();
	if(queryThreadInfo == nullptr)
	{
		debuggerMessage("getNtQueryInformationThread failed ", asHex(GetLastError()));
		return threadMemorySketch;
	}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
	if(hSnapshot == INVALID_HANDLE_VALUE)
	{
		debuggerMessage("CreateToolhelp32Snapshot failed ", asHex(GetLastError()));
		return threadMemorySketch;
	}

	threadInfo.dwSize = sizeof(THREADENTRY32);
	if(!Thread32First(hSnapshot, &threadInfo))
	{
		debuggerMessage("Thread32First failed ", asHex(GetLastError()));
		CloseHandle(hSnapshot);
		return threadMemorySketch;
	}
	do
	{
		THREAD_BASIC_INFORMATION threadBasicInfo;
		ULONG ret;
		HANDLE hThread;
		if(threadInfo.th32OwnerProcessID != processId)
			continue;

		hThread = OpenThread(THREAD_QUERY_INFORMATION,  FALSE, threadInfo.th32ThreadID);
		if(hThread == NULL)
		{	
			debuggerMessage("OpenThread failed ", threadInfo.th32ThreadID, " - ",GetLastError());
			continue;
		}

		if(!NT_SUCCESS(queryThreadInfo(hThread, ThreadBasicInformation, &threadBasicInfo, sizeof(THREAD_BASIC_INFORMATION), &ret)))
		{
			debuggerMessage("queryThreadInfo failed", GetLastError());
			CloseHandle(hThread);
			continue;
		}

		threadMemorySketch[threadBasicInfo.TebBaseAddress] = "Teb"; //TODO: add thread id to memory description;
		CloseHandle(hThread);
	}while(Thread32Next(hSnapshot, &threadInfo));

	CloseHandle(hSnapshot);
	return threadMemorySketch;
}

void Debugger::sketchMemoryTest()
{
	std::map<PVOID, std::string> mem = sketchMemory();
	for(auto i : mem)
		debuggerMessage(i.first, " - ", i.second);
}

void Debugger::exceptionEvent()
{
	EXCEPTION_RECORD *expceptionRecord = &debugEvent.u.Exception.ExceptionRecord;
	state = bpoint;
	debuggerMessage("Exception ", 
		asHex(expceptionRecord->ExceptionCode),
		" at address ", 
		expceptionRecord->ExceptionAddress);
}
void Debugger::createThreadEvent()
{
	debuggerMessage("New thread with id ", debugEvent.dwThreadId);
}

void Debugger::createProcessEvent()
{
	debuggerMessage("Create Process Event with id ", debugEvent.dwProcessId);
}

void Debugger::exitThreadEvent()
{
	debuggerMessage("Exiting thread with code ", debugEvent.u.ExitThread.dwExitCode);
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
    return procInfo.hProcess;
}

NtQueryInformationProcess Debugger::getNtQueryInformationProcess()
{
	HMODULE hNtdll = GetModuleHandle("ntdll");
	if(hNtdll == NULL)
		return nullptr;

	NtQueryInformationProcess func = (NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	return func;
}

NtQueryInformationThread Debugger::getNtQueryInformationThread()
{
	HMODULE hNtdll = GetModuleHandle("ntdll");
	if(hNtdll == NULL)
		return nullptr;

	NtQueryInformationThread func = (NtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
	return func;
}

PPEB Debugger::loadPeb() // loads peb data from debugged process to allocated(heap) buffer so later that memory should be realeased
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