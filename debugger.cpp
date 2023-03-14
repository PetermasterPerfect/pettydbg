#include "debugger.h"

Debugger::Debugger(const char *filePath) : CommandLineInput("Not running yet")  // filePath arg is basically cmd run by CreateProcess
{
	hProcess = startup(filePath);
	if(hProcess == NULL)
		fprintf(stderr, "startup failed [%lx]\n", GetLastError());

	printf("Running %s with id %i\n", filePath, GetProcessId(hProcess));
	isAttached = false;
	isRunning = false;
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
	isAttached = true;
	isRunning = true;
}

void Debugger::foolCin() // ***
{
	std::string buf;
	std::streambuf *backup = std::cin.rdbuf();
    std::istringstream iss("aaa\n");
    std::cin.rdbuf(iss.rdbuf());
	std::cin>>buf;
	std::cin.rdbuf(backup);
}

template<class... Args> void Debugger::debuggerPrint(Args... args)
{
	foolCin();
	(std::cout << ... << args) << std::endl;
}

template <typename T> std::string Debugger::asHex(T num)
{
	std::stringstream sstream;
	sstream << std::hex << num;
	return sstream.str();
}

void Debugger::handleCmd()
{
	argMutex.lock();
	//puts("handleCmd");
	if(cmdToHandle)
	{
		//puts("in cmdToHandle if");
		if(isRunning)
		{
			if(arguments[0] == "break")
				breakCommand();
			else
				debuggerPrint("Process is running, only available command is \"break\"");
		}
		else
		{
			if(arguments[0] == "run")
				runCommand();			
			else if(arguments[0] == "c")
				continueCommand();
			else
				debuggerPrint("Command isnt recognized");
		}
		arguments.clear();
		cmdToHandle = false;
	}
	argMutex.unlock();
}

void Debugger::enterDebuggerLoop()
{
	memset(&debugEvent, 0, sizeof(DEBUG_EVENT));
	while(true)
	{
		if(!WaitForDebugEvent(&debugEvent, 1000))
		{
			//fprintf(stderr, "WaitFordebugEvent error [%lx]\n", GetLastError());
			handleCmd();
		}
		
		switch(debugEvent.dwDebugEventCode)
		{
			
			case EXCEPTION_DEBUG_EVENT:
			{
				exceptionEvent();
				EXCEPTION_DEBUG_INFO& exception = debugEvent.u.Exception;
				switch( exception.ExceptionRecord.ExceptionCode)
				{
				case STATUS_BREAKPOINT:
					printf("breakpoint %i", debugEvent.dwThreadId	);
					break;

				default:
					if(exception.dwFirstChance == 1)
					{
						printf("first chance\n");
					}		
				}
				ContinueDebugEvent(debugEvent.dwProcessId, 
							debugEvent.dwThreadId,
							DBG_CONTINUE);
				break;
			}
			
			case CREATE_THREAD_DEBUG_EVENT:
			{
				createThreadEvent();
				ContinueDebugEvent(debugEvent.dwProcessId, 
					debugEvent.dwThreadId,
					DBG_CONTINUE);
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
				printf("default %x, %x:\n", debugEvent.dwDebugEventCode, debugEvent.u.Exception.ExceptionRecord.ExceptionCode);
			}
		}
	}

}

void Debugger::continueCommand()
{
	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	isRunning = true;
}

void Debugger::runCommand()
{
	fprintf(stderr, "xResumeThread %x ", ResumeThread(procInfo.hThread));
	ContinueDebugEvent(procInfo.dwProcessId, procInfo.dwThreadId, DBG_CONTINUE);
	statusMutex.lock();
	status = "Running";
	statusMutex.unlock();
	//foolCin();
	isRunning = true;
}

void Debugger::breakCommand()
{
	if(!DebugBreakProcess(hProcess))
		fprintf(stderr, "DebugBreakProcess failed %lx\n", GetLastError());
	
	statusMutex.lock();
	status = "Break";
	statusMutex.unlock();
	//foolCin();
	isRunning = false;
}

void Debugger::changeStatus(std::string newSt)
{
	statusMutex.lock();
	status = newSt;
	statusMutex.unlock();
}

void Debugger::exceptionEvent()
{
	EXCEPTION_RECORD *expceptionRecord = &debugEvent.u.Exception.ExceptionRecord;
	debuggerPrint("exceptionEvent");
	//changeStatus("Exception");
	isRunning = false;
	debuggerPrint("Exceptions code ", 
		asHex(expceptionRecord->ExceptionCode),
		" at address ", 
		expceptionRecord->ExceptionAddress);
	
	
}
void Debugger::createThreadEvent()
{
	debuggerPrint("New thread with id ", debugEvent.dwThreadId);
}

void Debugger::createProcessEvent()
{
	debuggerPrint("Starting process with id ", debugEvent.dwProcessId);
}

void Debugger::exitThreadEvent()
{
	debuggerPrint("Exiting thread with code ", debugEvent.u.ExitThread.dwExitCode);
}

void Debugger::exitProcessEvent()
{
	debuggerPrint("Exiting process with code ", debugEvent.u.ExitProcess.dwExitCode);
}

void Debugger::loadDllEvent()
{
	if(!isAttached)
	{
		debuggerPrint("loadDllEvent: TODO");
	}
}

void Debugger::unloadDllEvent()
{
	std::cout << "unloadDllEvent\n";
}

void Debugger::outputDebugStringEvent()
{
	std::cout << "outputDebugString\n";
}

void Debugger::ripEvent()
{
	std::cout << "RIP error number " << debugEvent.u.RipInfo.dwError << "\n";
}

HANDLE Debugger::startup(const char *cmdLine)
{
    STARTUPINFOA si;
    bool creationResult;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));

/*	si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
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
    return procInfo.hProcess;
}
