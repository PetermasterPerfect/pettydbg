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

void Debugger::foolCin()
{
	std::string buf;
	std::streambuf *backup = std::cin.rdbuf();
    std::istringstream iss("\n");
    std::cin.rdbuf(iss.rdbuf());
	std::cin>>buf;
	std::cin.rdbuf(backup);
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
				printf("Process is running, only available command is \"break\"\n");
		}
		else
		{
			if(arguments[0] == "run")
				runCommand();			
			if(arguments[0] == "c")
				continueCommand();
			else
			{
				foolCin();
				printf("Command isnt recognized\n");
			}
		}
		arguments.clear();
		cmdToHandle = false;
	}
	argMutex.unlock();
}

void Debugger::enterDebuggerLoop()
{
	//std::thread thInput(&Debugger::commandLineLoop, this);
	while(true)
	{
		if(!WaitForDebugEvent(&debugEvent, 100))
		{
			//fprintf(stderr, "WaitFordebugEvent error [%lx]\n", GetLastError());
			handleCmd();
		}
		switch(debugEvent.u.Exception.ExceptionRecord.ExceptionCode)
		{
			
			case EXCEPTION_DEBUG_EVENT:
			{
				exceptionEvent();
				break;
			}
			
			case CREATE_THREAD_DEBUG_EVENT:
			{
				createThreadEvent();
				break;
			}
			
			case CREATE_PROCESS_DEBUG_EVENT:
			{
				createProcessEvent();
				break;
			}
			
			case EXIT_THREAD_DEBUG_EVENT:
			{
				exitThreadEvent();
				break;
			}
			
			case EXIT_PROCESS_DEBUG_EVENT:
			{
				exitThreadEvent();
				break;
			}
			
			case LOAD_DLL_DEBUG_EVENT:
			{
				loadDllEvent();
				break;
			}
			
			case UNLOAD_DLL_DEBUG_EVENT:
			{
				unloadDllEvent();
				break;
			}
			case OUTPUT_DEBUG_STRING_EVENT:
			{
				outputDebugStringEvent();
				break;
			}
			case RIP_EVENT:
			{
				ripEvent();
				break;
			}			
			default:
			{
				//printf("default %x, %x:\n", debugEvent.dwDebugEventCode, debugEvent.u.Exception.ExceptionRecord.ExceptionCode);
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
	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	isRunning = true;
}

void Debugger::breakCommand()
{
	if(!DebugBreakProcess(hProcess))
		fprintf(stderr, "DebugBreakProcess failed %lx\n", GetLastError());
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
	std::cout << "exceptionEvent\n";
	changeStatus("Exception");
	isRunning = false;
	printf("Exceptions code %lx at address %p\n", expceptionRecord->ExceptionCode, expceptionRecord->ExceptionAddress);
	
	
}
void Debugger::createThreadEvent()
{
	std::cout << "New thread with id " << GetThreadId(debugEvent.u.CreateThread.hThread) << "\n";
}

void Debugger::createProcessEvent()
{
	std::cout << "Starting process with id " << GetProcessId(debugEvent.u.CreateProcessInfo.hProcess) << "\n";
}

void Debugger::exitThreadEvent()
{
	std::cout << "Exiting thread with code " << debugEvent.u.ExitThread.dwExitCode<< "\n";
}

void Debugger::exitProcessEvent()
{
	std::cout << "Exiting process with code " << debugEvent.u.ExitProcess.dwExitCode << "\n";
}

void Debugger::loadDllEvent()
{
	if(!isAttached)
	{
		std::cout << "loadDllEvent: TODO\n";
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
    PROCESS_INFORMATION pi;
    bool creationResult;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	si.dwFlags |= STARTF_USESTDHANDLES;
    creationResult = CreateProcessA
    (
        NULL,   // the path
        (char*)cmdLine,                // Command line
        NULL,                   // Process handle not inheritable
        NULL,                   // Thread handle not inheritable
        TRUE,                  // Set handle inheritance to FALSE
        DEBUG_PROCESS ,//| CREATE_SUSPENDED,
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory
        &si,            // Pointer to STARTUPINFO structure
        &pi           // Pointer to PROCESS_INFORMATION structure
        );

    return pi.hProcess;
}
