# pettydbg

**pettydbg** is a lightweight CLI debugger for **Windows x86-64**, inspired by `gdb` but intentionally small, educational, and minimalistic.  
Its purpose is to let you inspect instructions, step through execution, view registers, disassemble code, and read simple DWARF symbols — without the complexity of full-scale debuggers.

---

## 🚀 Features

- Debugs **Windows x86-64 PE** executables  
- Software breakpoints (`int 3`)
- Step into / step over / step out
- Register dump
- Stack inspection
- Instruction disassembly with **Zydis**
- DWARF debug info parsing with **libdwarf**
- CLI grammar implemented with **ANTLR4**

---

## 📦 Dependencies

pettydbg uses:

- **ANTLR4** – command parsing  
- **Zydis** – disassembly  
- **libdwarf** – DWARF debugging symbols  

Both Zydis and libdwarf are included in the repository as submodules.  
To download them, run:

```sh
git submodule update --init --recursive
```
The ANTLR4 JAR file is downloaded automatically during the CMake configuration step,
so Java must be installed for the build to succeed.

## Building
Building is done using Visual Studio.
To build pettydbg from source, run the following commands (as noted above, you must have Java installed):
```sh
git clone https://github.com/PetermasterPerfect/pettydbg
cd pettydbg
git submodule update --init --recursive
mkdir build
cd build
cmake -G "Visual Studio 17 2022" ..
```
---

## ⚠️ DWARF & Symbol Limitations

Current symbol support is intentionally minimal:

- Only simple C variables  
- Only **unsigned 8-byte variables** are fully supported  
  - Smaller types print extra bytes  
- No pointers  
- No structures  
- No arrays  
- No C++ support  

---

## 📝 Supported Commands

| Command | Syntax | Description |
|--------|--------|-------------|
| `ll` | `ll` | List source at current execution line |
| `c` | `c` | Continue execution |
| `r` | `r` | Restart program |
| `thinfo` | `thinfo` | List active threads |
| `meminfo` | `meminfo` | List memory mappings |
| `n` | `n` | Step over |
| `s` | `s` | Step into |
| `f` | `f` | Step out |
| `p` | `p <var>` | Print variable |
| `reg` | `reg` | Dump registers |
| `stack` | `stack <bytes>` | Display stack memory |
| `bp` | `bp <addr>` | Set breakpoint |
| `delbp` | `delbp <id>` | Delete breakpoint |
| `bpinfo` | `bpinfo` | List breakpoints |
| `dis` | `dis <addr> <bytes>` | Disassemble bytes |

---

## 🎥 Demo Video

The following intentionally simple program was used to demonstrate pettydbg’s stepping, breakpoints, register dumps, and symbol printing.
In the video, you can see that after hitting the system breakpoint, the first user-defined breakpoint is triggered by the inline assembly instruction (int3) inside the bar function.
I step out of this function using the "f" command (finish).

Next, I execute the "n" (step over) command, which steps over the instruction that increments the b3 variable.
After that, I print the contents of b3, and as expected, its value is 11.

Then I display the process memory mappings ("meminfo" command) and disassemble 60 bytes from the current instruction pointer("dis" command).
Using the disassembly, I set a breakpoint at the end of the loop("bp" command).

Now, when running the program with "c" (continue), each iteration of the loop prints a "." character to the debugged program’s console.
```c
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

void foo(size_t a1)
{
    size_t b1 = 3;
    c = b1 * a1 + rand();
}

size_t bar(size_t a2)
{
    size_t b2 = a2 + 1 + rand();
    __asm("int3");
    c = b2 * 10 ^ a2;
    return c - foo(b2);
}

size_t main(int arc, char *argv[])
{
    size_t a3 = rand();
    size_t b3 = 10;
    bar(a3 + 10);
    b3++;
    a3 += a3;
    foo(a3 - b3);

    while (1)
    {    
        Sleep(100);
        putchar('.');
    }

    if (a3 == 10)
        return a3;
    return 0;
}
```

I compiled this code with following command:
```c
gcc test.c -o test.exe -g
```

Demo (click to watch demo video on youtube):


[![DEMO](https://img.youtube.com/vi/hklohHHl2c8/0.jpg)](https://www.youtube.com/watch?v=hklohHHl2c8)
