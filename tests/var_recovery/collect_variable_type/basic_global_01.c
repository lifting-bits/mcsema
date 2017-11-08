#include <stdio.h>
int global_var_int = 100;
long global_var_long = 1000;
float global_var_float = 100.20;
double global_var_double = 100090.20202;


int main(int argc, char **argv)
{
	printf("global_var_int = %d\n", global_var_int);
	printf("global_var_long = %ld\n", global_var_long);
	printf("global_var_float = %9.6f\n", global_var_float);
	printf("global_var_double = %9.6f\n", global_var_double);
	return 0;
}
