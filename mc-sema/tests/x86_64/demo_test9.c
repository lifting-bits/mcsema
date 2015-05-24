#include <stdio.h>

void foo(void) {
    return;
}

int printit(char ch[]) {
	int c;

	c = printf("%s\n", ch);
	c = printf("%s, %s\n", ch, ch);
	c = printf("%s, %s, %s\n", ch, ch, ch);

	return c;
}

