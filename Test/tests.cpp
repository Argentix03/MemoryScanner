#include <stdio.h>
#include <Windows.h>

int test1();
int test2();
int g_a = 1337;
int g_b = 123456;
int g_c = 76453;

int main(int argc, char** argv)
{
	printf("PID: %d\n", GetCurrentProcessId());
	test1();
	//test2();

	return 0;
}

int test1()
{
	printf("Test 1: Simple Integer Test\n");

	int a = 13371;
	int b = 13372;
	int c = 13373;
	printf("var (local): a\tvalue: %d\taddress:%p\n", a, &a);
	printf("var (local): b\tvalue: %d\taddress:%p\n", b, &b);
	printf("var (local): c\tvalue: %d\taddress:%p\n", c, &c);
	printf("var (global): a\tvalue: %d\taddress:%p\n", g_a, &g_a);
	printf("var (global): b\tvalue: %d\taddress:%p\n", g_b, &g_b);
	printf("var (global): c\tvalue: %d\taddress:%p\n", g_c, &g_c);

	system("pause");

	a = 76453;
	g_a = 76453;
	printf("var (local): a\tvalue: %d\taddress:%p\n", a, &a);
	printf("var (local): b\tvalue: %d\taddress:%p\n", b, &b);
	printf("var (local): c\tvalue: %d\taddress:%p\n", c, &c);
	printf("var (global): a\tvalue: %d\taddress:%p\n", g_a, &g_a);
	printf("var (global): b\tvalue: %d\taddress:%p\n", g_b, &g_b);
	printf("var (global): c\tvalue: %d\taddress:%p\n", g_c, &g_c);

	system("pause");

	a = 123456;
	g_a = 76453;
	printf("var (local): a\tvalue: %d\taddress:%p\n", a, &a);
	printf("var (local): b\tvalue: %d\taddress:%p\n", b, &b);
	printf("var (local): c\tvalue: %d\taddress:%p\n", c, &c);
	printf("var (global): a\tvalue: %d\taddress:%p\n", g_a, &g_a);
	printf("var (global): b\tvalue: %d\taddress:%p\n", g_b, &g_b);
	printf("var (global): c\tvalue: %d\taddress:%p\n", g_c, &g_c);

	system("pause");

	return 1;
}

int test2()
{
	printf("Test 2: Simple Text Test\n");

	WCHAR a[] = L"DIANA";
	char b[6] = { 'D','I','A','N','A', 0 };
	char c[] = "1337";
	printf("var (local): a\tvalue: %ls\taddress:%p\n", a, &a);
	printf("var (local): b\tvalue: %s\taddress:%p\n", b, &b);
	printf("var (local): c\tvalue: %s\taddress:%p\n", c, &c);

	system("pause");

	b[0] = 'd', b[1] = 'i';
	printf("var (local): a\tvalue: %ls\taddress:%p\n", a, &a);
	printf("var (local): b\tvalue: %s\taddress:%p\n", b, &b);
	printf("var (local): c\tvalue: %s\taddress:%p\n", c, &c);

	system("pause");

	return 1;
}