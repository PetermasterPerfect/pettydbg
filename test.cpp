#include <cstdio>
#include <thread>
using namespace std;

void task1()
{
	while(1)
		putchar('#');
}


int main() {
	printf("%p\n", main); // 0x401544
	int a=1;
	int b=0;
	std::thread t1(task1);
	while(1)
	{
		// __asm( ".intel_syntax noprefix;\n\t"
		// 	"pushf\n\t"
		// 	"pop r15\n\t"
		// 	"or r15, 0x100\n\t"
		// 	"push r15\n\t"
		// 	"popf\n\t"
		// 	);
		//__asm("int3");
		//__asm("pop rax");
		b-=2;
		a+=1;
		// __asm("pushf");
		// __asm("or 0x100, word [$sp]");
		// __asm("popf");
		putchar('.');

	}
    return 0;
}