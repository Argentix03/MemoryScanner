// TODO:
// Modules
// MMF
// Static variables in functions
// Stack
// Heap
// Pointer paths (eg. Engine->map->mob->player, Engine->players->player, ...)
// Rotate locations (defence) 

#include <stdio.h>
#include <Windows.h>

int testInt();
int testPointers();
int g_a = 1337;
int g_b = 123456;
int g_c = 76453;
int* g_pointerA;
int* g_pointerB;

int main(int argc, char** argv)
{
	printf("PID: %d\n", GetCurrentProcessId());
	int userChoice;
	while (true) {
		printf(
			"Choose an option:\n"
			"1: Test basic Int\n"
			"2: Test Pointers\n"
		);
		scanf_s("%d", &userChoice);
		switch (userChoice)
		{
		case 1:
			testInt();
			break;
		case 2:
			testPointers();
			break;
		default:
			printf("Invalid choice\n");
		}
	}
	testInt();


	return 0;
}

int testInt()
{
	printf("Test 1: Simple Integer Test\n");

	int a = 13371;
	int b = 13372;
	int c = 13373;
	printf("var [INT] (local): a\tvalue: %d\taddress:%p\n", a, &a);
	printf("var [INT] (local): b\tvalue: %d\taddress:%p\n", b, &b);
	printf("var [INT] (local): c\tvalue: %d\taddress:%p\n", c, &c);
	printf("var [INT] (global): a\tvalue: %d\taddress:%p\n", g_a, &g_a);
	printf("var [INT] (global): b\tvalue: %d\taddress:%p\n", g_b, &g_b);
	printf("var [INT] (global): c\tvalue: %d\taddress:%p\n", g_c, &g_c);

	system("pause");

	a = 76453;
	g_a = 76453;
	Sleep(500); 
	printf("var [INT] (local): a\tvalue: %d\taddress:%p\n", a, &a);
	printf("var [INT] (local): b\tvalue: %d\taddress:%p\n", b, &b);
	printf("var [INT] (local): c\tvalue: %d\taddress:%p\n", c, &c);
	printf("var [INT] (global): a\tvalue: %d\taddress:%p\n", g_a, &g_a);
	printf("var [INT] (global): b\tvalue: %d\taddress:%p\n", g_b, &g_b);
	printf("var [INT] (global): c\tvalue: %d\taddress:%p\n", g_c, &g_c);
	
	system("pause");

	a = 123456;
	g_a = 76453;
	Sleep(500);
	printf("var [INT] (local): a\tvalue: %d\taddress:%p\n", a, &a);
	printf("var [INT] (local): b\tvalue: %d\taddress:%p\n", b, &b);
	printf("var [INT] (local): c\tvalue: %d\taddress:%p\n", c, &c);
	printf("var [INT] (global): a\tvalue: %d\taddress:%p\n", g_a, &g_a);
	printf("var [INT] (global): b\tvalue: %d\taddress:%p\n", g_b, &g_b);
	printf("var [INT] (global): c\tvalue: %d\taddress:%p\n", g_c, &g_c);

	system("pause");

	return 1;
}

int testPointers()
{
	printf("Test 2: Simple Pointer Test\n");

	int intA = 13371;
	int intB = 13372;
	int* pointerA = &intA;
	int* pointerB = &intB;
	printf("var [INT] (local): a\tvalue: %d\taddress:%p\n", intA, &intA);
	printf("var [INT] (global): c\tvalue: %d\taddress:%p\n", intB, &intB);
	printf("var [pointer] (local): a\tvalue: 0x%p\taddress:%p\n", pointerA, &pointerA);
	printf("var [pointer] (global): c\tvalue: 0x%p\taddress:%p\n", pointerB, &pointerB);
	printf("var [INT] (global): a\tvalue: 0x%p\taddress:%p\n", g_pointerA, &g_pointerA);
	printf("var [INT] (global): b\tvalue: 0x%p\taddress:%p\n", g_pointerB, &g_pointerB);

	system("pause");

	intA = 123456;
	intB = 123457;
	g_a = 1;
	Sleep(500);
	printf("var [INT] (local): a\tvalue: %d\taddress:%p\n", intA, &intA);
	printf("var [INT] (global): c\tvalue: %d\taddress:%p\n", intB, &intB);
	printf("var [pointer] (local): a\tvalue: 0x%p\taddress:%p\n", pointerA, &pointerA);
	printf("var [pointer] (global): c\tvalue: 0x%p\taddress:%p\n", pointerB, &pointerB);
	printf("var [INT] (global): a\tvalue: 0x%p\taddress:%p\n", g_pointerA, &g_pointerA);
	printf("var [INT] (global): b\tvalue: 0x%p\taddress:%p\n", g_pointerB, &g_pointerB);

	system("pause");

	intA = 4321;
	intB = 4322;
	g_b = 2;
	Sleep(500);
	printf("var [INT] (local): a\tvalue: %d\taddress:%p\n", intA, &intA);
	printf("var [INT] (global): c\tvalue: %d\taddress:%p\n", intB, &intB);
	printf("var [pointer] (local): a\tvalue: 0x%p\taddress:%p\n", pointerA, &pointerA);
	printf("var [pointer] (global): c\tvalue: 0x%p\taddress:%p\n", pointerB, &pointerB);
	printf("var [INT] (global): a\tvalue: 0x%p\taddress:%p\n", g_pointerA, &g_pointerA);
	printf("var [INT] (global): b\tvalue: 0x%p\taddress:%p\n", g_pointerB, &g_pointerB);

	system("pause");

	return 1;
}