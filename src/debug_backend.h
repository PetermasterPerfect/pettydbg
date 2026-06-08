#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include "registers.h"

enum class StopReason
{
	None,
	Breakpoint,
	SingleStep,
	Signal,
	Exited
};

struct EventInfo
{
	StopReason reason = StopReason::None;
	uint64_t threadId = 0;
	uintptr_t address = 0;
	int exitStatus = 0;
	int signalNumber = 0;
};

class IDebugBackend
{
public:
	virtual ~IDebugBackend() = default;

	virtual uint64_t getProcessId() const = 0;
	virtual uint64_t getCurrentThreadId() const = 0;
	virtual bool isAttached() const = 0;
	virtual bool isRunning() const = 0;

	virtual bool startProcess(const std::string& cmd) = 0;
	virtual bool attachProcess(uint64_t pid) = 0;
	virtual void terminate() = 0;
	virtual bool restart() = 0;

	virtual bool continueExecution() = 0;
	virtual bool singleStep(uint64_t threadId) = 0;
	virtual void sendBreakSignal() = 0;

	virtual EventInfo waitForEvent(bool blocking) = 0;

	virtual bool readMemory(uintptr_t address, void* buffer, size_t size, size_t* bytesRead = nullptr) = 0;
	virtual bool writeMemory(uintptr_t address, const void* buffer, size_t size, size_t* bytesWritten = nullptr) = 0;

	virtual bool getRegisters(uint64_t threadId, Registers& regs) = 0;
	virtual bool setRegisters(uint64_t threadId, const Registers& regs) = 0;

	virtual std::vector<uint64_t> listThreads() = 0;
	virtual std::vector<std::string> getMemoryMappings() = 0;

	virtual std::string getTargetPath() = 0;
	virtual uintptr_t getImageBase() = 0;
	virtual uintptr_t getLinkBase() = 0;
	virtual size_t getImageSize() = 0;
};
