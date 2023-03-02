#include "debugger.h"

VOID Debugger::enterDebuggerLoop()
{
	DEBUG_EVENT debugEv;
	while(true)
	{
		if(!WaitForDebugEvent(&debugEv, 10000))
			fprintf(stderr, "WaitFordebugEvent failed [%lx]\n", GetLastError());
		switch(debugEv.u.Exception.ExceptionRecord.ExceptionCode)
		{
			default:
			{
				printf("%x, %x:\n", debugEv.dwDebugEventCode, debugEv.u.Exception.ExceptionRecord.ExceptionCode);
			}
		}
	}
			
}

Debugger::Debugger(const char *filePath)
{
	hProcess = startup(filePath);
	if(hProcess == NULL)
		fprintf(stderr, "startup failed [%lx]\n", GetLastError());
	
	isAttached = FALSE;
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
	isAttached = TRUE;
}

HANDLE Debugger::startup(const char *cmdLine)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    BOOL creationResult;
	
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