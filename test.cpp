#include <cstdio>
#include <windows.h>

// x86_64-w64-mingw32-g++ test.cpp -o test.exe

int main()
{
	while(1)
	{
		Sleep(2000);
		putchar('.');
	}
}