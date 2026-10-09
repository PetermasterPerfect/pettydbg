int foo(int a, int b)
{
	int total = a + b;
	return total * 2;
}

int main()
{
	int left = 4;
	int right = 6;
	int result = foo(left, right);
	__asm__("int3");
	return result == 20 ? 0 : 1;
}
