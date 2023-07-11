@echo off
bash -c "x86_64-w64-mingw32-g++ main.cpp debugger.cpp commandline.cpp splitstring.cpp unicodeStringEx.cpp -o dbg.exe -static -std=c++17 -I capstone/include -L capstone -lcapstone"
bash -c "x86_64-w64-mingw32-g++ -static test.cpp -o test.exe -masm=intel -g"
