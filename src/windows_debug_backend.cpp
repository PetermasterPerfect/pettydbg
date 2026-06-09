#ifdef _WIN32

#include "windows_debug_backend.h"
#include "unicodeStringEx.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <codecvt>
#include <locale>

WindowsDebugBackend::WindowsDebugBackend() = default;

WindowsDebugBackend::~WindowsDebugBackend()
{
	terminate();
}

SmartHandle WindowsDebugBackend::startup(const wchar_t* cmdLine)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION procInfo;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&procInfo, sizeof(PROCESS_INFORMATION));

	bool creationResult = CreateProcessW(
		NULL,
		(LPWSTR)cmdLine,
		NULL,
		NULL,
		FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&procInfo);

	if (!creationResult)
	{
		std::cerr << "CreateProcessW failed: " << GetLastError() << "\n";
		return nullptr;
	}

	processId = procInfo.dwProcessId;
	CloseHandle(procInfo.hThread);
	return SmartHandle(procInfo.hProcess);
}

bool WindowsDebugBackend::startProcess(const std::string& cmd)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	initialCmdW = L"\"" + converter.from_bytes(cmd) + L"\"";
	isAttached_ = false;

	hProcess = startup(initialCmdW.c_str());
	if (!hProcess)
		return false;

	refreshTargetInfo();
	running = false;
	return true;
}

bool WindowsDebugBackend::attachProcess(uint64_t pid)
{
	isAttached_ = true;
	processId = static_cast<DWORD>(pid);
	hProcess = SmartHandle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId));
	if (!hProcess)
		return false;

	if (!DebugActiveProcess(processId))
		return false;

	refreshTargetInfo();
	running = false;
	return true;
}

void WindowsDebugBackend::terminate()
{
	if (hProcess)
	{
		if (isAttached_)
			DebugActiveProcessStop(processId);
		else
			TerminateProcess(hProcess.get(), 0);
		hProcess.reset();
		processId = 0;
		running = false;
	}
}

bool WindowsDebugBackend::restart()
{
	if (isAttached_)
	{
		std::cerr << "Cannot restart debuggee: process was attached.\n";
		return false;
	}
	if (initialCmdW.empty())
		return false;

	terminate();
	hProcess = startup(initialCmdW.c_str());
	if (!hProcess)
		return false;

	refreshTargetInfo();
	running = false;
	return true;
}

bool WindowsDebugBackend::continueExecution()
{
	if (!hProcess)
		return false;

	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	running = true;
	return true;
}

bool WindowsDebugBackend::singleStep(uint64_t threadId)
{
	DWORD tid = threadId ? static_cast<DWORD>(threadId) : debugEvent.dwThreadId;
	SmartHandle hT = getThreadHandle(tid);
	if (!hT)
		return false;

	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (!GetThreadContext(hT.get(), &ctx))
		return false;

	ctx.EFlags |= 0x100; // set trap flag

	if (!SetThreadContext(hT.get(), &ctx))
		return false;

	ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	running = true;
	return true;
}

void WindowsDebugBackend::sendBreakSignal()
{
	if (hProcess)
		DebugBreakProcess(hProcess.get());
}

EventInfo WindowsDebugBackend::waitForEvent(bool blocking)
{
	EventInfo event;
	DWORD timeout = blocking ? INFINITE : 10;

	if (!WaitForDebugEvent(&debugEvent, timeout))
		return event;

	event.threadId = debugEvent.dwThreadId;

	switch (debugEvent.dwDebugEventCode)
	{
	case EXCEPTION_DEBUG_EVENT:
	{
		EXCEPTION_DEBUG_INFO& exception = debugEvent.u.Exception;
		event.address = reinterpret_cast<uintptr_t>(exception.ExceptionRecord.ExceptionAddress);

		if (exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT)
		{
			running = false;
			event.reason = StopReason::Breakpoint;
		}
		else if (exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
		{
			running = false;
			event.reason = StopReason::SingleStep;
		}
		else
		{
			running = false;
			event.reason = StopReason::Signal;
			event.signalNumber = static_cast<int>(exception.ExceptionRecord.ExceptionCode);
		}
		break;
	}
	case EXIT_PROCESS_DEBUG_EVENT:
	{
		running = false;
		event.reason = StopReason::Exited;
		event.exitStatus = static_cast<int>(debugEvent.u.ExitProcess.dwExitCode);
		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
		break;
	}
	case CREATE_PROCESS_DEBUG_EVENT:
	case CREATE_THREAD_DEBUG_EVENT:
	case EXIT_THREAD_DEBUG_EVENT:
	case LOAD_DLL_DEBUG_EVENT:
	case UNLOAD_DLL_DEBUG_EVENT:
	case OUTPUT_DEBUG_STRING_EVENT:
	case RIP_EVENT:
	default:
		ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
		break;
	}

	return event;
}

bool WindowsDebugBackend::readMemory(uintptr_t address, void* buffer, size_t size, size_t* bytesRead)
{
	if (!hProcess)
		return false;

	SIZE_T read = 0;
	BOOL res = ReadProcessMemory(hProcess.get(), reinterpret_cast<LPCVOID>(address), buffer, size, &read);
	if (bytesRead)
		*bytesRead = static_cast<size_t>(read);
	return res != FALSE;
}

bool WindowsDebugBackend::writeMemory(uintptr_t address, const void* buffer, size_t size, size_t* bytesWritten)
{
	if (!hProcess)
		return false;

	SIZE_T written = 0;
	BOOL res = WriteProcessMemory(hProcess.get(), reinterpret_cast<LPVOID>(address), buffer, size, &written);
	if (bytesWritten)
		*bytesWritten = static_cast<size_t>(written);
	return res != FALSE;
}

bool WindowsDebugBackend::getRegisters(uint64_t threadId, Registers& regs)
{
	DWORD tid = threadId ? static_cast<DWORD>(threadId) : debugEvent.dwThreadId;
	SmartHandle hT = getThreadHandle(tid);
	if (!hT)
		return false;

	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(hT.get(), &ctx))
		return false;

	regs.rax = ctx.Rax;
	regs.rbx = ctx.Rbx;
	regs.rcx = ctx.Rcx;
	regs.rdx = ctx.Rdx;
	regs.rsi = ctx.Rsi;
	regs.rdi = ctx.Rdi;
	regs.rbp = ctx.Rbp;
	regs.rsp = ctx.Rsp;
	regs.r8 = ctx.R8;
	regs.r9 = ctx.R9;
	regs.r10 = ctx.R10;
	regs.r11 = ctx.R11;
	regs.r12 = ctx.R12;
	regs.r13 = ctx.R13;
	regs.r14 = ctx.R14;
	regs.r15 = ctx.R15;
	regs.rip = ctx.Rip;
	regs.rflags = ctx.EFlags;
	return true;
}

bool WindowsDebugBackend::setRegisters(uint64_t threadId, const Registers& regs)
{
	DWORD tid = threadId ? static_cast<DWORD>(threadId) : debugEvent.dwThreadId;
	SmartHandle hT = getThreadHandle(tid);
	if (!hT)
		return false;

	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(hT.get(), &ctx))
		return false;

	ctx.Rax = regs.rax;
	ctx.Rbx = regs.rbx;
	ctx.Rcx = regs.rcx;
	ctx.Rdx = regs.rdx;
	ctx.Rsi = regs.rsi;
	ctx.Rdi = regs.rdi;
	ctx.Rbp = regs.rbp;
	ctx.Rsp = regs.rsp;
	ctx.R8 = regs.r8;
	ctx.R9 = regs.r9;
	ctx.R10 = regs.r10;
	ctx.R11 = regs.r11;
	ctx.R12 = regs.r12;
	ctx.R13 = regs.r13;
	ctx.R14 = regs.r14;
	ctx.R15 = regs.r15;
	ctx.Rip = regs.rip;
	ctx.EFlags = static_cast<DWORD>(regs.rflags);

	return SetThreadContext(hT.get(), &ctx) != FALSE;
}

SmartHandle WindowsDebugBackend::getThreadHandle(DWORD threadId)
{
	auto threads = listActiveThreadHandles();
	auto it = threads.find(threadId);
	if (it != threads.end())
		return std::move(it->second);
	return SmartHandle(OpenThread(THREAD_ALL_ACCESS, FALSE, threadId));
}

std::map<DWORD, SmartHandle> WindowsDebugBackend::listActiveThreadHandles()
{
	std::map<DWORD, SmartHandle> activeThreads;
	SmartHandle hSnap = SmartHandle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId));
	if (!hSnap)
		return activeThreads;

	THREADENTRY32 info;
	info.dwSize = sizeof(THREADENTRY32);
	if (!Thread32First(hSnap.get(), &info))
		return activeThreads;

	do
	{
		if (info.th32OwnerProcessID == processId)
			activeThreads[info.th32ThreadID] = SmartHandle(OpenThread(THREAD_ALL_ACCESS, FALSE, info.th32ThreadID));
	} while (Thread32Next(hSnap.get(), &info));

	return activeThreads;
}

std::vector<uint64_t> WindowsDebugBackend::listThreads()
{
	std::vector<uint64_t> result;
	auto threads = listActiveThreadHandles();
	for (const auto& pair : threads)
		result.push_back(pair.first);
	return result;
}

std::vector<std::string> WindowsDebugBackend::getMemoryMappings()
{
	std::vector<std::string> results;
	if (!hProcess)
		return results;

	SIZE_T startAddr = 0;
	MEMORY_BASIC_INFORMATION memInfo;
	memset(&memInfo, 0, sizeof(MEMORY_BASIC_INFORMATION));
	std::map<PVOID, std::string> memoryDescription = sketchMemory();

	while (VirtualQueryEx(hProcess.get(), (LPCVOID)startAddr, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		std::stringstream descStream;
		descStream << "0x" << std::hex << (uintptr_t)memInfo.BaseAddress << "\t"
			<< std::setw(16) << "0x" << std::hex << memInfo.RegionSize << "\t"
			<< memStateAsString(memInfo.State) << "\t"
			<< memTypeAsString(memInfo.Type);

		if (memoryDescription.find(memInfo.BaseAddress) != memoryDescription.end())
			descStream << "\t" << memoryDescription[memInfo.BaseAddress];

		results.push_back(descStream.str());
		startAddr += memInfo.RegionSize;
	}
	return results;
}

NtQueryInformationProcess WindowsDebugBackend::getNtQueryInformationProcess()
{
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if (!hNtdll)
		return nullptr;
	return (NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
}

std::unique_ptr<PEB> WindowsDebugBackend::loadPeb(SIZE_T* addr)
{
	if (!hProcess)
		return nullptr;

	auto queryInfoProc = getNtQueryInformationProcess();
	if (!queryInfoProc)
		return nullptr;

	PROCESS_BASIC_INFORMATION procInfo;
	ULONG ret = 0;
	NTSTATUS status = queryInfoProc(hProcess.get(), ProcessBasicInformation, &procInfo, sizeof(PROCESS_BASIC_INFORMATION), &ret);
	if (!NT_SUCCESS(status))
		return nullptr;

	if (addr)
		*addr = (SIZE_T)procInfo.PebBaseAddress;

	std::unique_ptr<PEB> peb(new PEB);
	SIZE_T read = 0;
	if (!ReadProcessMemory(hProcess.get(), procInfo.PebBaseAddress, peb.get(), sizeof(PEB), &read))
		return nullptr;

	return peb;
}

std::unique_ptr<RTL_USER_PROCESS_PARAMETERS> WindowsDebugBackend::loadProcessParameters()
{
	auto peb = loadPeb();
	if (!peb)
		return nullptr;

	std::unique_ptr<RTL_USER_PROCESS_PARAMETERS> procParams(new RTL_USER_PROCESS_PARAMETERS);
	SIZE_T read = 0;
	if (!ReadProcessMemory(hProcess.get(), peb->ProcessParameters, procParams.get(), sizeof(RTL_USER_PROCESS_PARAMETERS), &read))
		return nullptr;

	return procParams;
}

void WindowsDebugBackend::refreshTargetInfo()
{
	if (!hProcess)
		return;

	// ImageBase from PEB
	auto peb = loadPeb();
	if (peb)
		imageBase = peb->ImageBaseAddress;

	// Target path
	DWORD pathlen = 32767;
	std::vector<char> pathBuf(pathlen);
	if (QueryFullProcessImageNameA(hProcess.get(), 0, pathBuf.data(), &pathlen))
	{
		targetPath = std::string(pathBuf.data());
	}

	// Read NT headers
	if (!targetPath.empty())
	{
		std::ifstream f(targetPath, std::ios::binary);
		if (f.is_open())
		{
			IMAGE_DOS_HEADER dosHdr;
			f.read(reinterpret_cast<char*>(&dosHdr), sizeof(dosHdr));
			f.seekg(dosHdr.e_lfanew);
			f.read(reinterpret_cast<char*>(&ntHdr), sizeof(ntHdr));
			linkBase = ntHdr.OptionalHeader.ImageBase;
			imageSize = ntHdr.OptionalHeader.SizeOfImage;
		}
	}
}

std::string WindowsDebugBackend::memStateAsString(DWORD state)
{
	if (state == MEM_COMMIT)
		return "MEM_COMMIT";
	if (state == MEM_FREE)
		return "MEM_FREE";
	if (state == MEM_RESERVE)
		return "MEM_RESERVE";
	return "NONE STATE";
}

std::string WindowsDebugBackend::memTypeAsString(DWORD state)
{
	if (state == MEM_IMAGE)
		return "MEM_IMAGE";
	if (state == MEM_MAPPED)
		return "MEM_MAPPED";
	if (state == MEM_PRIVATE)
		return "MEM_PRIVATE";
	return "NONE TYPE";
}

std::map<PVOID, std::string> WindowsDebugBackend::sketchMemory()
{
	std::map<PVOID, std::string> memorySketch;
	SIZE_T pebAddr = 0;
	auto peb = loadPeb(&pebAddr);
	if (peb)
		memorySketch[(PVOID)pebAddr] = "PEB";

	return memorySketch;
}

#endif // _WIN32
