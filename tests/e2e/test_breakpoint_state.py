import sys

from debugger import Debugger


def main():
    if len(sys.argv) != 3:
        print("usage: test_breakpoint_state.py <debugger> <debuggee>", file=sys.stderr)
        return 2

    debugger_path, debuggee_path = sys.argv[1:]
    try:
        with Debugger(debugger_path, debuggee_path) as dbg:
            state = dbg.assert_state(debuggee_path=debuggee_path)
            rip = state.registers["Rip"]
            dbg.set_breakpoint(rip)
            output = dbg.continue_execution()
            assert "Breakpoint hit at address" in output, output
            dbg.step_over()
            state2 = dbg.assert_state(debuggee_path=debuggee_path)
            assert state2.registers.get("Rip") is not None
    except Exception as exc:  # intentionally diagnostic
        print(f"breakpoint state test failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
