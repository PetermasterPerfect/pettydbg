#pragma once
#ifdef __linux__

#include "debug_backend.h"
#include <sys/types.h>
#include <string>
#include <vector>

class LinuxDebugBackend : public IDebugBackend
{
public:
	LinuxDebugBackend();
	~LinuxDebugBackend() override;

	uint64_t getProcessId() const override { return processId; }
	uint64_t getCurrentThreadId() const override { return currentThreadId; }
	bool isAttached() const override { return isAttached_; }
	bool isRunning() const override { return running; }

	bool startProcess(const std::string& cmd) override;
	bool attachProcess(uint64_t pid) override;
	void terminate() override;
	bool restart() override;

	bool continueExecution() override;
	virtual bool singleStep(uint64_t threadId) override;
	void sendBreakSignal() override;

	EventInfo waitForEvent(bool blocking) override;

	bool readMemory(uintptr_t address, void* buffer, size_t size, size_t* bytesRead = nullptr) override;
	bool writeMemory(uintptr_t address, const void* buffer, size_t size, size_t* bytesWritten = nullptr) override;

	bool getRegisters(uint64_t threadId, Registers& regs) override;
	bool setRegisters(uint64_t threadId, const Registers& regs) override;

	std::vector<uint64_t> listThreads() override;
	std::vector<std::string> getMemoryMappings() override;

	std::string getTargetPath() override { return targetPath; }
	uintptr_t getImageBase() override { return imageBase; }
	uintptr_t getLinkBase() override { return linkBase; }
	size_t getImageSize() override { return imageSize; }

private:
	pid_t processId = 0;
	pid_t currentThreadId = 0;
	bool isAttached_ = false;
	bool running = false;
	std::string initialCmd;

	std::string targetPath;
	uintptr_t imageBase = 0;
	uintptr_t linkBase = 0;
	size_t imageSize = 0;

	void refreshTargetInfo();
	bool writeMemoryWord(uintptr_t address, const void* buffer, size_t size);
};

#endif // __linux__
