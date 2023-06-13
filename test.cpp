#include <cstdio>
#include <thread>
using namespace std;

void task1()
{
	while(1)
		putchar('#');
}


int main() {
	int a=1;
	int b=0;
	std::thread t1(task1);
	while(1)
	{
		// *(int*)0xccccc = 1;
		// __asm("int3");
		putchar('.');
	}
    return 0;
}