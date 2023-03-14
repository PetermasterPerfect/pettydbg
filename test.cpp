#include <cstdio>
using namespace std;

int main() {
	int a=1;
	int b=0;
	while(1)
	{
		*(int*)0xccccc = 1;
		//__asm("int3");
		putchar('.');
	}
    return 0;
}