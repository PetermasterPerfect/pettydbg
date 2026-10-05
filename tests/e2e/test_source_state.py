import sys

from debugger import Debugger


def main():
    if len(sys.argv) != 3:
        print("usage: test_source_state.py <debugger> <debuggee>", file=sys.stderr)
        return 2

    debugger_path, debuggee_path = sys.argv[1:]
    try:
        with Debugger(debugger_path, debuggee_path) as dbg:
            state = dbg.assert_state(debuggee_path=debuggee_path)
            source = dbg.source(20)
            assert "main" in source or "foo" in source or "result" in source, source
            assert "Breakpoint hit at address" in dbg.continue_execution()
            value = dbg.print_variable("result")
            assert "result" in value, value
    except Exception as exc:  # intentionally diagnostic
        print(f"source state test failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
