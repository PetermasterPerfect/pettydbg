#include "debugger.h"
extern Debugger *dbg;

BOOL WINAPI registerSignals(DWORD dwCtrlType)
{
		if(dwCtrlType == CTRL_C_EVENT)
		{
			DebugActiveProcessStop(dbg->procInfo.dwProcessId);
			ExitProcess(0xcc);
		}
		else if (dwCtrlType == CTRL_BREAK_EVENT)
		{
			if(dbg->status!="Break")
				dbg->breakSignal();
		}
		return TRUE;
}

Debugger::Debugger(const char *filePath) : CommandLineInput("Not running yet")  // filePath arg is basically cmd run by CreateProcess
{
	hProcess = startup(filePath);
	if(hProcess == NULL)
		fprintf(stderr, "startup failed [%lx]\n", GetLastError());

	printf("Running %s with id %i\n", filePath, GetProcessId(hProcess));
	isRunning = false;
	SetConsoleCtrlHandler(registerSignals, TRUE);
}

Debugger::Debugger(DWORD pid) : CommandLineInput("Running")
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
	isRunning = true;
	SetConsoleCtrlHandler(registerSignals, TRUE);
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
		if(isRunning == false)
		{
			commandLineInterface();
			if(cmdToHandle == true)
				handleCmd();		
		}		
		WaitForDebugEvent(&debugEvent, 1);
		exceptionSwitchedCased();
	}
}

void Debugger::handleCmd()
{
	if(cmdToHandle && arguments.size() >= 1)
	{
		if(arguments[0] == "run")
		{
			runCommand();
		}
		else if(arguments[0] == "c")
			continueCommand();
		else if(arguments[0] == "thinfo")
			enumerateThreadsCommand();
		else
			debuggerMessage("Command isnt recognized");
		arguments.clear();
		cmdToHandle = false;
	}
}

void Debugger::exceptionSwitchedCased()
{
	if(status == "Not running yet")
		return;
	
	switch(debugEvent.dwDebugEventCode)
	{
		
		case EXCEPTION_DEBUG_EVENT:
		{
			exceptionEvent();
			EXCEPTION_DEBUG_INFO& exception = debugEvent.u.Exception;
			switch( exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_BREAKPOINT:
				debuggerMessage("breakpoint, thread id ", debugEvent.dwThreadId);
				break;

			default:
				if(exception.dwFirstChance == 1)
				{
					debuggerMessage("first chance");
				}		
			}
			if(exception.dwFirstChance == 1)
			{
				debuggerMessage("first chance");
				//ContinueDebugEvent(debugEvent.dwProcessId, 
				//		debugEvent.dwThreadId,
				//		DBG_CONTINUE);
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
			loadDllEvent();
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
	status = "Running";
	debuggerMessage("c command ", debugEvent.dwThreadId);
	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	isRunning = true;
}

void Debugger::runCommand()
{
	status = "Running";
	ContinueDebugEvent(procInfo.dwProcessId, procInfo.dwThreadId, DBG_CONTINUE);
	isRunning = true;
}

void Debugger::breakSignal()
{
	if(!DebugBreakProcess(hProcess))
		return;
	status = "Break";
	isRunning = false;
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

void Debugger::exceptionEvent()
{
	EXCEPTION_RECORD *expceptionRecord = &debugEvent.u.Exception.ExceptionRecord;
	debuggerMessage("exceptionEvent");
	isRunning = false;
	status = "Break";
	debuggerMessage("Exceptions code ", 
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
	status = "Exit";
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

HANDLE Debugger::startup(const char *cmdLine)
{
    STARTUPINFOA si;
    bool creationResult;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));

/*	si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	si.hStdInput = GetStdHandle(ST
	D_INPUT_HANDLE);
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	si.dwFlags |= STARTF_USESTDHANDLES;*/
    creationResult = CreateProcessA
    (
        (char*)cmdLine,   // the path
        NULL,                // Command line
        NULL,                   // Process handle not inheritable
        NULL,                   // Thread handle not inheritable
        FALSE,                  // Set handle inheritance to FALSE
        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory
        &si,            // Pointer to STARTUPINFO structure
        &procInfo           // Pointer to PROCESS_INFORMATION structure
        );
	printf("creationResult %i\n", creationResult);
	processId = procInfo.dwProcessId;
    return procInfo.hProcess;
}
