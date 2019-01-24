#include <stdio.h>

int main()
{
	for (int i = 0; i < 13; ++i)
	{
		int a;
		switch (i)
		{
		case 1:
			a = 1;
			break;
		case 2:
			a = 2;
			break;
		case 3:
			a = 3;
			break;
		case 4:
			a = 4;
			break;
		case 5:
			a = 5;
			break;
		case 6:
			a = 6;
			break;
		case 7:
			a = 7;
			break;
		case 8:
			a = 8;
			break;
		default:
			a = 0;
			break;
		}
		printf("%d\n", a);
	}
}
