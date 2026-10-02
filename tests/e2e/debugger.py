import queue
import re
import subprocess
import threading
import time
from dataclasses import dataclass


_PROMPT = b">>> "
_REGISTER = re.compile(r"^([A-Za-z][A-Za-z0-9 ]*)=\s*(0x[0-9a-fA-F]+)$")
_THREAD = re.compile(r"^Thread -\s*(\d+)$")
_STACK_ENTRY = re.compile(r"^(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)$")
_BREAKPOINT = re.compile(r"^Breakpoint at (0x[0-9a-fA-F]+)$")
_INSTRUCTION = re.compile(r"^([0-9A-Fa-f]{8,16})\s+(.*)$")


@dataclass(frozen=True)
class StackEntry:
    address: int
    value: int


@dataclass(frozen=True)
class Instruction:
    address: int
    text: str


@dataclass(frozen=True)
class DebuggerSnapshot:
    registers: dict
    threads: list[int]
    memory: list[str]
    stack: list[StackEntry]
    disassembly: list[Instruction]


class Debugger:
    """Interactive client for pettydbg's line-oriented command interface."""

    def __init__(self, debugger_path, debuggee_path, timeout=10):
        self.timeout = timeout
        self._output = queue.Queue()
        self._process = subprocess.Popen(
            [debugger_path, debuggee_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        self._reader = threading.Thread(target=self._read_output, daemon=True)
        self._reader.start()
        try:
            self._read_until_prompt()
        except (RuntimeError, TimeoutError):
            if self._process.poll() is None:
                self._process.terminate()
                self._process.wait()
            self._process.stdin.close()
            self._reader.join(timeout=self.timeout)
            raise

    def _read_output(self):
        while True:
            char = self._process.stdout.read(1)
            if not char:
                self._output.put(None)
                return
            self._output.put(char)

    def _read_until_prompt(self):
        deadline = time.monotonic() + self.timeout
        response = bytearray()
        while not response.endswith(_PROMPT):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for debugger prompt")
            try:
                char = self._output.get(timeout=remaining)
            except queue.Empty as error:
                raise TimeoutError("timed out waiting for debugger prompt") from error
            if char is None:
                output = response.decode(errors="replace")
                raise RuntimeError(
                    f"debugger exited before prompt "
                    f"(status {self._process.poll()}):\n{output}"
                )
            response.extend(char)
        return response[:-len(_PROMPT)].decode(errors="replace")

    def command(self, command):
        """Send one debugger command and return its unparsed output."""
        if self._process.poll() is not None:
            raise RuntimeError("debugger process is not running")
        try:
            self._process.stdin.write((command + "\n").encode())
            self._process.stdin.flush()
        except OSError as error:
            raise RuntimeError(f"could not send debugger command {command!r}") from error
        return self._read_until_prompt()

    def continue_execution(self):
        return self.command("c")

    def continue_(self):
        return self.continue_execution()

    def step_over(self):
        return self.command("n")

    def step_into(self):
        return self.command("s")

    def finish(self):
        return self.command("f")

    def set_breakpoint(self, address):
        return self.command(f"bp {address:#x}")

    def delete_breakpoint(self, address):
        return self.command(f"delbp {address:#x}")

    def breakpoint_info(self):
        output = self.command("bpinfo")
        return [
            int(match.group(1), 16)
            for line in output.splitlines()
            if (match := _BREAKPOINT.match(line.strip()))
        ]

    def memory_info(self):
        return self._output_lines("meminfo")

    def threads(self):
        output = self.command("thinfo")
        return [
            int(match.group(1))
            for line in output.splitlines()
            if (match := _THREAD.match(line.strip()))
        ]

    def source(self, lines=10):
        return self.command(f"ll {lines}")

    def registers(self):
        output = self.command("reg")
        parsed = {}
        for line in output.splitlines():
            match = _REGISTER.match(line.strip())
            if match:
                name = match.group(1).strip()
                parsed[name] = int(match.group(2), 16)
        return parsed

    def stack(self, words=10):
        output = self.command(f"stack {words}")
        entries = []
        for line in output.splitlines():
            match = _STACK_ENTRY.match(line.strip())
            if match:
                entries.append(
                    StackEntry(int(match.group(1), 16), int(match.group(2), 16))
                )
        return entries

    def disassemble(self, address, size):
        output = self.command(f"dis {address:#x} {size}")
        instructions = []
        for line in output.splitlines():
            match = _INSTRUCTION.match(line.strip())
            if match:
                instructions.append(
                    Instruction(int(match.group(1), 16), match.group(2))
                )
        return instructions

    def print_variable(self, name):
        return self.command(f"p ${name}")

    def locals(self):
        return self.command("lvar")

    def _output_lines(self, command):
        return [line for line in self.command(command).splitlines() if line.strip()]

    def exit(self):
        """Exit pettydbg and return any output emitted while shutting down."""
        if self._process.poll() is not None:
            return ""
        try:
            self._process.stdin.write(b"exit\n")
            self._process.stdin.flush()
            self._process.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired as error:
            self._process.terminate()
            self._process.wait()
            raise TimeoutError("debugger did not exit after the exit command") from error
        finally:
            self._process.stdin.close()

        output = bytearray()
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out reading debugger output")
            try:
                char = self._output.get(timeout=remaining)
            except queue.Empty as error:
                raise TimeoutError("timed out reading debugger output") from error
            if char is None:
                break
            output.extend(char)
        return output.decode(errors="replace")

    def snapshot(self):
        registers = self.registers()
        threads = self.threads()
        memory = self.memory_info()
        stack = self.stack(4)
        disassembly = self.disassemble(registers.get("Rip", 0), 16)
        return DebuggerSnapshot(
            registers=registers,
            threads=threads,
            memory=memory,
            stack=stack,
            disassembly=disassembly,
        )

    def assert_state(self, *, debuggee_path, expected_threads_min=1, expected_stack_min=1, expect_rip_nonzero=True):
        snapshot = self.snapshot()
        assert snapshot.registers, "register state was empty"
        if expect_rip_nonzero:
            assert snapshot.registers.get("Rip", 0) != 0, "RIP should be non-zero at the breakpoint"
        assert len(snapshot.threads) >= expected_threads_min, f"expected >= {expected_threads_min} thread(s), got {snapshot.threads}"
        assert any(debuggee_path in line for line in snapshot.memory), f"debuggee mapping not found in memory output: {snapshot.memory}"
        assert any("r-xp" in line for line in snapshot.memory), f"executable mapping missing from memory output: {snapshot.memory}"
        assert len(snapshot.stack) >= expected_stack_min, f"expected >= {expected_stack_min} stack entries, got {snapshot.stack}"
        assert snapshot.disassembly, "disassembly output was empty"
        assert any(
            any(token in instr.text.lower() for token in ("mov", "call", "add", "sub", "ret"))
            for instr in snapshot.disassembly
        ), f"disassembly did not contain expected instructions: {snapshot.disassembly}"
        return snapshot

    def close(self):
        if self._process.poll() is None:
            self.exit()
        elif not self._process.stdin.closed:
            self._process.stdin.close()
        self._reader.join(timeout=self.timeout)
        if self._reader.is_alive():
            self._process.stdout.close()
            self._reader.join(timeout=self.timeout)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
