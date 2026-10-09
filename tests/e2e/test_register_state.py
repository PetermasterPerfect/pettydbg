import sys

from debugger import Debugger


def main():
    if len(sys.argv) != 3:
        print("usage: test_register_state.py <debugger> <debuggee>", file=sys.stderr)
        return 2

    debugger_path, debuggee_path = sys.argv[1:]
    try:
        with Debugger(debugger_path, debuggee_path) as dbg:
            state = dbg.assert_state(debuggee_path=debuggee_path)
            assert state.registers.get("Rip") is not None
            assert state.registers.get("Rsp") is not None
            assert len(state.stack) >= 2
            assert len(state.memory) >= 4
            assert state.disassembly
    except Exception as exc:  # intentionally diagnostic
        print(f"register state test failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
