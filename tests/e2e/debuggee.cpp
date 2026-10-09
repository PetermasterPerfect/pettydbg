static int compute(int left, int right)
{
	int sum = left + right;
	int product = sum * 3;
	__asm__("int3");
	return product;
}

int main()
{
	int left = 7;
	int right = 5;
	int result = compute(left, right);
	return result == 36 ? 0 : 1;
}
