#pragma once
#ifdef _WIN32

#include "debug_backend.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include "peb.h"
#include "thread_info.h"

struct SmartHandleDeleter
{
	BOOL operator()(HANDLE h) const {
		return CloseHandle(h);
	}
};
using SmartHandle = std::unique_ptr<void, SmartHandleDeleter>;

class WindowsDebugBackend : public IDebugBackend
{
public:
	WindowsDebugBackend();
	~WindowsDebugBackend() override;

	uint64_t getProcessId() const override { return processId; }
	uint64_t getCurrentThreadId() const override { return debugEvent.dwThreadId; }
	bool isAttached() const override { return isAttached_; }
	bool isRunning() const override { return running; }

	bool startProcess(const std::string& cmd) override;
	bool attachProcess(uint64_t pid) override;
	void terminate() override;
	bool restart() override;

	bool continueExecution() override;
	bool singleStep(uint64_t threadId) override;
	void sendBreakSignal() override;

	EventInfo waitForEvent(bool blocking) override;

	bool readMemory(uintptr_t address, void* buffer, size_t size, size_t* bytesRead = nullptr) override;
	bool writeMemory(uintptr_t address, const void* buffer, size_t size, size_t* bytesWritten = nullptr) override;

	bool getRegisters(uint64_t threadId, Registers& regs) override;
	bool setRegisters(uint64_t threadId, const Registers& regs) override;

	std::vector<uint64_t> listThreads() override;
	std::vector<std::string> getMemoryMappings() override;

	std::string getTargetPath() override { return targetPath; }
	uintptr_t getImageBase() override { return reinterpret_cast<uintptr_t>(imageBase); }
	uintptr_t getLinkBase() override { return linkBase; }
	size_t getImageSize() override { return imageSize; }

	HANDLE getProcessHandle() const { return hProcess.get(); }

private:
	DWORD processId = 0;
	SmartHandle hProcess;
	bool isAttached_ = false;
	bool running = false;
	DEBUG_EVENT debugEvent = {};

	std::wstring initialCmdW;
	std::string targetPath;
	PVOID imageBase = nullptr;
	uintptr_t linkBase = 0;
	size_t imageSize = 0;
	IMAGE_NT_HEADERS ntHdr = {};

	SmartHandle startup(const wchar_t*);
	void refreshTargetInfo();
	std::unique_ptr<PEB> loadPeb(SIZE_T* addr = nullptr);
	std::unique_ptr<RTL_USER_PROCESS_PARAMETERS> loadProcessParameters();
	NtQueryInformationProcess getNtQueryInformationProcess();
	SmartHandle getThreadHandle(DWORD threadId);
	std::map<DWORD, SmartHandle> listActiveThreadHandles();
	std::map<PVOID, std::string> sketchMemory();
	std::string memStateAsString(DWORD state);
	std::string memTypeAsString(DWORD state);
};

#endif // _WIN32
