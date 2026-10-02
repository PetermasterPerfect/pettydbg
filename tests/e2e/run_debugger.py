import sys

from debugger import Debugger


def main():
    if len(sys.argv) != 3:
        print("usage: run_debugger.py <debugger> <debuggee>", file=sys.stderr)
        return 2

    debugger_path, debuggee_path = sys.argv[1:]
    try:
        with Debugger(debugger_path, debuggee_path) as debugger:
            state = debugger.assert_state(debuggee_path=debuggee_path)
            if "Rip" not in state.registers:
                raise AssertionError(f"register output has no instruction pointer: {state.registers}")

            instruction_pointer = state.registers["Rip"]
            debugger.set_breakpoint(instruction_pointer)
            if instruction_pointer not in debugger.breakpoint_info():
                raise AssertionError("breakpoint was not listed after being set")

            exit_output = ""
            for _ in range(6):
                out = debugger.continue_execution()
                exit_output += out
                if "Process exited with code 0" in out:
                    break
            else:
                raise AssertionError(f"debuggee did not reach a clean exit after repeated continue calls: {exit_output!r}")

            if "Process exited with code 0" not in exit_output:
                raise AssertionError(f"debuggee did not exit successfully: {exit_output!r}")
    except (OSError, RuntimeError, TimeoutError, AssertionError) as error:
        print(f"debugger end-to-end test failed: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
