#include <gtest/gtest.h>
#include "debug_backend.h"
#include <map>
#include <cstring>

class MockDebugBackend : public IDebugBackend
{
public:
	uint64_t pid = 1234;
	uint64_t tid = 1234;
	bool running = false;
	Registers regs;
	std::map<uintptr_t, uint8_t> memory;

	uint64_t getProcessId() const override { return pid; }
	uint64_t getCurrentThreadId() const override { return tid; }
	bool isAttached() const override { return false; }
	bool isRunning() const override { return running; }

	bool startProcess(const std::string& cmd) override { running = true; return true; }
	bool attachProcess(uint64_t p) override { pid = p; running = true; return true; }
	void terminate() override { running = false; }
	bool restart() override { return true; }

	bool continueExecution() override { running = true; return true; }
	bool singleStep(uint64_t t) override { return true; }
	void sendBreakSignal() override {}

	EventInfo waitForEvent(bool blocking) override { return EventInfo{}; }

	bool readMemory(uintptr_t address, void* buffer, size_t size, size_t* bytesRead = nullptr) override
	{
		uint8_t* dst = static_cast<uint8_t*>(buffer);
		for (size_t i = 0; i < size; ++i)
		{
			auto it = memory.find(address + i);
			if (it != memory.end())
				dst[i] = it->second;
			else
				dst[i] = 0;
		}
		if (bytesRead) *bytesRead = size;
		return true;
	}

	bool writeMemory(uintptr_t address, const void* buffer, size_t size, size_t* bytesWritten = nullptr) override
	{
		const uint8_t* src = static_cast<const uint8_t*>(buffer);
		for (size_t i = 0; i < size; ++i)
			memory[address + i] = src[i];
		if (bytesWritten) *bytesWritten = size;
		return true;
	}

	bool getRegisters(uint64_t t, Registers& r) override { r = regs; return true; }
	bool setRegisters(uint64_t t, const Registers& r) override { regs = r; return true; }

	std::vector<uint64_t> listThreads() override { return { tid }; }
	std::vector<std::string> getMemoryMappings() override { return {}; }

	std::string getTargetPath() override { return "/dummy/target"; }
	uintptr_t getImageBase() override { return 0x400000; }
	uintptr_t getLinkBase() override { return 0x400000; }
	size_t getImageSize() override { return 0x1000; }
};

TEST(MockBackendTest, ReadAndWriteMemory)
{
	MockDebugBackend backend;
	uint32_t val = 0xDEADBEEF;
	EXPECT_TRUE(backend.writeMemory(0x5000, &val, sizeof(val)));

	uint32_t readVal = 0;
	EXPECT_TRUE(backend.readMemory(0x5000, &readVal, sizeof(readVal)));
	EXPECT_EQ(readVal, 0xDEADBEEF);
}

TEST(MockBackendTest, GetAndSetRegisters)
{
	MockDebugBackend backend;
	Registers r;
	r.rip = 0x401050;
	r.rax = 42;
	EXPECT_TRUE(backend.setRegisters(backend.getCurrentThreadId(), r));

	Registers readRegs;
	EXPECT_TRUE(backend.getRegisters(backend.getCurrentThreadId(), readRegs));
	EXPECT_EQ(readRegs.rip, 0x401050u);
	EXPECT_EQ(readRegs.rax, 42u);
}
