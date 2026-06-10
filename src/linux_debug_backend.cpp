#ifdef __linux__

#include "linux_debug_backend.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <elf.h>
#include <signal.h>
#include <cstring>
#include <cerrno>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

static std::vector<std::string> splitCommandLine(const std::string& cmd)
{
	std::vector<std::string> args;
	std::string current;
	bool inQuotes = false;
	char quoteChar = 0;

	for (size_t i = 0; i < cmd.size(); ++i)
	{
		char c = cmd[i];
		if ((c == '"' || c == '\'') && !inQuotes)
		{
			inQuotes = true;
			quoteChar = c;
		}
		else if (inQuotes && c == quoteChar)
		{
			inQuotes = false;
		}
		else if (std::isspace(static_cast<unsigned char>(c)) && !inQuotes)
		{
			if (!current.empty())
			{
				args.push_back(current);
				current.clear();
			}
		}
		else
		{
			current.push_back(c);
		}
	}
	if (!current.empty())
		args.push_back(current);

	return args;
}

LinuxDebugBackend::LinuxDebugBackend() = default;

LinuxDebugBackend::~LinuxDebugBackend()
{
	terminate();
}

bool LinuxDebugBackend::startProcess(const std::string& cmd)
{
	initialCmd = cmd;
	isAttached_ = false;

	auto args = splitCommandLine(cmd);
	if (args.empty())
		return false;

	pid_t pid = fork();
	if (pid == -1)
		return false;

	if (pid == 0)
	{
		// In child
		if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
			_exit(1);

		std::vector<char*> argv;
		for (auto& s : args)
			argv.push_back(const_cast<char*>(s.c_str()));
		argv.push_back(nullptr);

		execvp(argv[0], argv.data());
		_exit(127);
	}

	// In parent
	processId = pid;
	currentThreadId = pid;

	int status = 0;
	if (waitpid(processId, &status, 0) == -1)
		return false;

	ptrace(PTRACE_SETOPTIONS, processId, 0,
		PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXIT);

	running = false;
	refreshTargetInfo();
	return true;
}

bool LinuxDebugBackend::attachProcess(uint64_t pid)
{
	initialCmd.clear();
	isAttached_ = true;
	processId = static_cast<pid_t>(pid);
	currentThreadId = processId;

	if (ptrace(PTRACE_ATTACH, processId, nullptr, nullptr) == -1)
		return false;

	int status = 0;
	if (waitpid(processId, &status, 0) == -1)
		return false;

	ptrace(PTRACE_SETOPTIONS, processId, 0,
		PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXIT);

	running = false;
	refreshTargetInfo();
	return true;
}

void LinuxDebugBackend::terminate()
{
	if (processId > 0)
	{
		if (isAttached_)
		{
			ptrace(PTRACE_DETACH, processId, nullptr, nullptr);
		}
		else
		{
			kill(processId, SIGKILL);
			int status;
			waitpid(processId, &status, WNOHANG);
		}
		processId = 0;
		currentThreadId = 0;
		running = false;
	}
}

bool LinuxDebugBackend::restart()
{
	if (isAttached_)
	{
		std::cerr << "Cannot restart debuggee: process was attached.\n";
		return false;
	}
	if (initialCmd.empty())
		return false;

	terminate();
	return startProcess(initialCmd);
}

bool LinuxDebugBackend::continueExecution()
{
	if (processId <= 0)
		return false;

	pid_t tid = currentThreadId ? currentThreadId : processId;
	if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1)
		return false;

	running = true;
	return true;
}

bool LinuxDebugBackend::singleStep(uint64_t threadId)
{
	pid_t tid = threadId ? static_cast<pid_t>(threadId) : (currentThreadId ? currentThreadId : processId);
	if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) == -1)
		return false;

	running = true;
	return true;
}

void LinuxDebugBackend::sendBreakSignal()
{
	if (processId > 0)
		kill(processId, SIGSTOP);
}

EventInfo LinuxDebugBackend::waitForEvent(bool blocking)
{
	EventInfo event;
	if (processId <= 0)
		return event;

	int options = blocking ? 0 : WNOHANG;
	int status = 0;
	pid_t wpid = waitpid(-1, &status, options | __WALL);
	if (wpid <= 0)
		return event;

	currentThreadId = wpid;

	if (WIFEXITED(status))
	{
		running = false;
		event.reason = StopReason::Exited;
		event.threadId = wpid;
		event.exitStatus = WEXITSTATUS(status);
		if (wpid == processId)
			processId = 0;
		return event;
	}

	if (WIFSIGNALED(status))
	{
		running = false;
		event.reason = StopReason::Exited;
		event.threadId = wpid;
		event.signalNumber = WTERMSIG(status);
		if (wpid == processId)
			processId = 0;
		return event;
	}

	if (WIFSTOPPED(status))
	{
		running = false;
		int sig = WSTOPSIG(status);
		int ptraceEvent = (status >> 16) & 0xff;

		if (ptraceEvent == PTRACE_EVENT_CLONE || ptraceEvent == PTRACE_EVENT_FORK)
		{
			unsigned long newTid = 0;
			ptrace(PTRACE_GETEVENTMSG, wpid, 0, &newTid);
			ptrace(PTRACE_CONT, wpid, nullptr, nullptr);
			running = true;
			return waitForEvent(blocking);
		}
		if (ptraceEvent == PTRACE_EVENT_EXIT)
		{
			ptrace(PTRACE_CONT, wpid, nullptr, nullptr);
			running = true;
			return waitForEvent(blocking);
		}

		Registers regs;
		if (getRegisters(wpid, regs))
			event.address = regs.rip;

		event.threadId = wpid;
		event.signalNumber = sig;

		if (sig == SIGTRAP)
		{
			event.reason = StopReason::Breakpoint;
		}
		else
		{
			event.reason = StopReason::Signal;
		}
		return event;
	}

	return event;
}

bool LinuxDebugBackend::readMemory(uintptr_t address, void* buffer, size_t size, size_t* bytesRead)
{
	if (processId <= 0 || size == 0)
		return false;

	struct iovec localIov = { buffer, size };
	struct iovec remoteIov = { reinterpret_cast<void*>(address), size };
	ssize_t n = process_vm_readv(processId, &localIov, 1, &remoteIov, 1, 0);
	if (n > 0)
	{
		if (bytesRead) *bytesRead = static_cast<size_t>(n);
		return true;
	}

	std::string memPath = "/proc/" + std::to_string(processId) + "/mem";
	int fd = open(memPath.c_str(), O_RDONLY);
	if (fd >= 0)
	{
		ssize_t res = pread(fd, buffer, size, address);
		close(fd);
		if (res > 0)
		{
			if (bytesRead) *bytesRead = static_cast<size_t>(res);
			return true;
		}
	}

	// Fallback to word-by-word PTRACE_PEEKTEXT
	uint8_t* dst = static_cast<uint8_t*>(buffer);
	for (size_t i = 0; i < size; ++i)
	{
		uintptr_t targetAddr = address + i;
		uintptr_t alignedAddr = targetAddr & ~(sizeof(long) - 1);
		size_t byteOffset = targetAddr % sizeof(long);

		errno = 0;
		long word = ptrace(PTRACE_PEEKTEXT, currentThreadId ? currentThreadId : processId, alignedAddr, 0);
		if (word == -1 && errno != 0)
			return false;

		dst[i] = reinterpret_cast<uint8_t*>(&word)[byteOffset];
	}
	if (bytesRead) *bytesRead = size;
	return true;
}

bool LinuxDebugBackend::writeMemory(uintptr_t address, const void* buffer, size_t size, size_t* bytesWritten)
{
	if (processId <= 0 || size == 0)
		return false;

	// For small writes (like software breakpoints 1 byte), writeMemoryWord using PTRACE_POKETEXT
	// is much more reliable as it bypasses page protection on text segments.
	if (size <= sizeof(long))
	{
		if (writeMemoryWord(address, buffer, size))
		{
			if (bytesWritten) *bytesWritten = size;
			return true;
		}
	}

	struct iovec localIov = { const_cast<void*>(buffer), size };
	struct iovec remoteIov = { reinterpret_cast<void*>(address), size };
	ssize_t n = process_vm_writev(processId, &localIov, 1, &remoteIov, 1, 0);
	if (n > 0)
	{
		if (bytesWritten) *bytesWritten = static_cast<size_t>(n);
		return true;
	}

	std::string memPath = "/proc/" + std::to_string(processId) + "/mem";
	int fd = open(memPath.c_str(), O_RDWR);
	if (fd >= 0)
	{
		ssize_t res = pwrite(fd, buffer, size, address);
		close(fd);
		if (res > 0)
		{
			if (bytesWritten) *bytesWritten = static_cast<size_t>(res);
			return true;
		}
	}

	if (writeMemoryWord(address, buffer, size))
	{
		if (bytesWritten) *bytesWritten = size;
		return true;
	}

	return false;
}

bool LinuxDebugBackend::writeMemoryWord(uintptr_t address, const void* buffer, size_t size)
{
	const uint8_t* src = static_cast<const uint8_t*>(buffer);
	pid_t tid = currentThreadId ? currentThreadId : processId;

	for (size_t i = 0; i < size; ++i)
	{
		uintptr_t targetAddr = address + i;
		uintptr_t alignedAddr = targetAddr & ~(sizeof(long) - 1);
		size_t byteOffset = targetAddr % sizeof(long);

		errno = 0;
		long word = ptrace(PTRACE_PEEKTEXT, tid, alignedAddr, 0);
		if (word == -1 && errno != 0)
			return false;

		uint8_t* wordBytes = reinterpret_cast<uint8_t*>(&word);
		wordBytes[byteOffset] = src[i];

		if (ptrace(PTRACE_POKETEXT, tid, alignedAddr, word) == -1)
			return false;
	}
	return true;
}

bool LinuxDebugBackend::getRegisters(uint64_t threadId, Registers& regs)
{
	pid_t tid = threadId ? static_cast<pid_t>(threadId) : (currentThreadId ? currentThreadId : processId);
	struct user_regs_struct uregs;
	if (ptrace(PTRACE_GETREGS, tid, 0, &uregs) == -1)
		return false;

	regs.rax = uregs.rax;
	regs.rbx = uregs.rbx;
	regs.rcx = uregs.rcx;
	regs.rdx = uregs.rdx;
	regs.rsi = uregs.rsi;
	regs.rdi = uregs.rdi;
	regs.rbp = uregs.rbp;
	regs.rsp = uregs.rsp;
	regs.r8 = uregs.r8;
	regs.r9 = uregs.r9;
	regs.r10 = uregs.r10;
	regs.r11 = uregs.r11;
	regs.r12 = uregs.r12;
	regs.r13 = uregs.r13;
	regs.r14 = uregs.r14;
	regs.r15 = uregs.r15;
	regs.rip = uregs.rip;
	regs.rflags = uregs.eflags;
	return true;
}

bool LinuxDebugBackend::setRegisters(uint64_t threadId, const Registers& regs)
{
	pid_t tid = threadId ? static_cast<pid_t>(threadId) : (currentThreadId ? currentThreadId : processId);
	struct user_regs_struct uregs;
	if (ptrace(PTRACE_GETREGS, tid, 0, &uregs) == -1)
		return false;

	uregs.rax = regs.rax;
	uregs.rbx = regs.rbx;
	uregs.rcx = regs.rcx;
	uregs.rdx = regs.rdx;
	uregs.rsi = regs.rsi;
	uregs.rdi = regs.rdi;
	uregs.rbp = regs.rbp;
	uregs.rsp = regs.rsp;
	uregs.r8 = regs.r8;
	uregs.r9 = regs.r9;
	uregs.r10 = regs.r10;
	uregs.r11 = regs.r11;
	uregs.r12 = regs.r12;
	uregs.r13 = regs.r13;
	uregs.r14 = regs.r14;
	uregs.r15 = regs.r15;
	uregs.rip = regs.rip;
	uregs.eflags = regs.rflags;

	return (ptrace(PTRACE_SETREGS, tid, 0, &uregs) == 0);
}

std::vector<uint64_t> LinuxDebugBackend::listThreads()
{
	std::vector<uint64_t> threads;
	if (processId <= 0)
		return threads;

	std::string taskPath = "/proc/" + std::to_string(processId) + "/task";
	DIR* dir = opendir(taskPath.c_str());
	if (!dir)
		return threads;

	struct dirent* entry;
	while ((entry = readdir(dir)) != nullptr)
	{
		if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9')
		{
			threads.push_back(std::stoull(entry->d_name));
		}
	}
	closedir(dir);
	return threads;
}

std::vector<std::string> LinuxDebugBackend::getMemoryMappings()
{
	std::vector<std::string> maps;
	if (processId <= 0)
		return maps;

	std::string mapsPath = "/proc/" + std::to_string(processId) + "/maps";
	std::ifstream file(mapsPath);
	std::string line;
	while (std::getline(file, line))
	{
		maps.push_back(line);
	}
	return maps;
}

void LinuxDebugBackend::refreshTargetInfo()
{
	if (processId <= 0)
		return;

	// 1. Get target binary path from /proc/<pid>/exe
	char exePath[4096] = {0};
	std::string linkPath = "/proc/" + std::to_string(processId) + "/exe";
	ssize_t len = readlink(linkPath.c_str(), exePath, sizeof(exePath) - 1);
	if (len > 0)
	{
		exePath[len] = '\0';
		targetPath = std::string(exePath);
	}

	// 2. Read /proc/<pid>/maps to locate imageBase and imageSize
	std::string mapsPath = "/proc/" + std::to_string(processId) + "/maps";
	std::ifstream mapsFile(mapsPath);
	std::string line;
	uintptr_t firstStart = 0;
	uintptr_t lastEnd = 0;

	while (std::getline(mapsFile, line))
	{
		if (targetPath.empty() || line.find(targetPath) != std::string::npos)
		{
			std::stringstream ss(line);
			std::string range;
			if (ss >> range)
			{
				size_t dash = range.find('-');
				if (dash != std::string::npos)
				{
					uintptr_t start = std::stoull(range.substr(0, dash), nullptr, 16);
					uintptr_t end = std::stoull(range.substr(dash + 1), nullptr, 16);

					if (firstStart == 0 || start < firstStart)
						firstStart = start;
					if (end > lastEnd)
						lastEnd = end;
				}
			}
		}
	}

	imageBase = firstStart;
	imageSize = (lastEnd > firstStart) ? (lastEnd - firstStart) : 0;

	// 3. Inspect ELF header of target binary
	linkBase = 0;
	if (!targetPath.empty())
	{
		std::ifstream elfFile(targetPath, std::ios::binary);
		if (elfFile.is_open())
		{
			Elf64_Ehdr ehdr;
			elfFile.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
			if (elfFile && memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0)
			{
				if (ehdr.e_type == ET_EXEC)
				{
					// For non-PIE executables, read program headers to find the lowest PT_LOAD virtual address
					elfFile.seekg(ehdr.e_phoff);
					uintptr_t lowestVaddr = 0;
					for (int i = 0; i < ehdr.e_phnum; ++i)
					{
						Elf64_Phdr phdr;
						elfFile.read(reinterpret_cast<char*>(&phdr), sizeof(phdr));
						if (phdr.p_type == PT_LOAD)
						{
							if (lowestVaddr == 0 || phdr.p_vaddr < lowestVaddr)
								lowestVaddr = phdr.p_vaddr;
						}
					}
					linkBase = lowestVaddr;
				}
				else
				{
					// For PIE (ET_DYN), linkBase is 0
					linkBase = 0;
				}
			}
		}
	}
}

#endif // __linux__
