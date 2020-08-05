/* TAGS: min c */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/* TEST: */
/* STDIN: Finputs/calc_input1.txt */
/* TEST: */
/* STDIN: Finputs/calc_input2.txt */
/* TEST: */
/* STDIN: Finputs/calc_input3.txt */
/* TEST: */
/* STDIN: Finputs/calc_input4.txt */
/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>

int sum();
int difference();
float divideFloat();
int divideInt();
int modulo();
int times();
long power();
long long int factorial();
int sums();
float average();
long long int binomialCoeficient();
int is_prime();
long long int factorialWithArgument(int a);
void cleanInput();

int main(void) {
	char c;
	do {
		printf("> ");
		c = getchar();
		switch (c) {
		case '+':
			printf("# sum\n");
			printf("# %i\n", sum());
			break;
		case '-':
			printf("# difference\n");
			printf("# %i\n", difference());
			break;
		case '/':
			printf("# %.2f\n", divideFloat());
			break;
		case 'd':
			printf("# %i\n", divideInt());
			break;
		case 'm':
			printf("# %i\n", modulo());
			break;
		case '*':
			printf("# %i\n", times());
			break;
		case '^':
			printf("# %li\n", power());
			break;
		case '!':
			printf("# %lli\n", factorial());
			break;
		case 's':
			printf("# %i\n", sums());
			break;
		case 'a':
			printf("# %.2f\n", average());
			break;
		case 'c':
			printf("# %lli\n", binomialCoeficient());

			break;
		case 'p':
			if (is_prime()) {
				printf("# y\n");
			} else {
				printf("# n\n");
			}
			break;
		default:
			break;
		}
		cleanInput();

	} while (c != 'q');
	return 0;
}

void cleanInput() {
	while (getchar() != '\n')
		;
}

int sum() {
	int a, b;
	scanf(" %i %i", &a, &b);
	return (a + b);
}

int difference() {
	int a, b;
	scanf(" %i %i", &a, &b);
	return (a - b);
}

float divideFloat() {
	float a, b;
	scanf(" %f %f", &a, &b);
	return (a / b);
}

int divideInt() {
	float a, b;
	scanf(" %f %f", &a, &b);
	return (a / b);
}

int modulo() {
	int a, b;
	scanf(" %i %i", &a, &b);
	return (a % b);
}

int times() {
	int a, b;
	scanf(" %i %i", &a, &b);
	return (a * b);
}

long int power() {
	int base, exp, result = 1;
	scanf(" %i %i", &base, &exp);
	if (exp == 0)
		return 1;
	for (int i = 1; i <= exp; i++) {
		result *= base;
	}
	return result;
}

long long int factorial() {
	int number;
	long long int result = 1;
	scanf(" %i", &number);
	if (number < 0) {
		return -1;
	} else if (number == 0) {
		return 1;
	} else {
		for (int i = 0; i < number; i++) {
			result *= (number - i);
		}
		return result;
	}
}

int sums() {
	int member, result = 0, numberOfMembers;
	scanf(" %i", &numberOfMembers);
	int temp = numberOfMembers;
	while (temp > 0) {
		scanf("%i", &member);
		result += member;
		temp--;
	}
	return result;
}

float average() {
	float result = 0;
	int member, numberOfMembers;
	scanf(" %i", &numberOfMembers);
	int temp = numberOfMembers;
	if (numberOfMembers == 0) {
		return 0;
	} else {
		while (temp > 0) {
			scanf(" %i", &member);
			result += member;
			--temp;
		}
		return (result / numberOfMembers);
	}
}

long long int binomialCoeficient() {
	int n, k;
	scanf(" %i %i", &n, &k);
	if (n < k || k < 0 || n < 0) {
		return -1;
	}
	long long int test = (factorialWithArgument(n) / (factorialWithArgument(n - k) * factorialWithArgument(k)));
	return test;
}

int is_prime() {
	int a;
	scanf(" %i", &a);
	if (a <= 1)
		return 0;
	for (int i = 2; i < a; i++) {
		if (a % i == 0)
			return 0;
	}
	return 1;
}

long long int factorialWithArgument(int a) {
	long long int result = 1;
	if (a < 0) {
		return -1;
	} else if (a == 0) {
		return 1;
	} else {
		for (int i = 0; i < a; i++) {
			result *= (a - i);
		}
		return result;
	}
}
