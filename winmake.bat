@echo off
rem for /f %i in ('cd') do set dir=%i
set dir=C:\Users\asus\Desktop\p.kajda\ReCraft\pettydbg
cd c:\MinGW\bin
g++ %dir%\main.cpp %dir%\debugger.cpp %dir%\commandline.cpp %dir%\splitstring.cpp %dir%\unicodeStringEx.cpp -o %dir%\dbg.exe -static -std=c++17 -I %dir%\capstone\include -L %dir%\capstone -lcapstone
cd %dir%