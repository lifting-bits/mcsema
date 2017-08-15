/*
 * basic_global_arrays.c
 *
 *  Created on: Aug 4, 2017
 *      Author: akkumar
 */

#include <stdio.h>

unsigned long global_var1 = 0;
unsigned long global_var2 = 0;
unsigned long global_var3 = 0;
unsigned long global_var4 = 0;

unsigned long *var_array[] = {
    &global_var1,
    &global_var2,
    &global_var3,
    &global_var4
};

unsigned long var_array_const[] = {
    10,
    20,
    30,
    40
};

struct variable_addresses {
 unsigned long *a;
 unsigned long *b;
 unsigned long *c;
};

struct variable_addresses var_test = {&global_var1, &global_var2, &global_var3};
struct variable_addresses arr_test = {&var_array_const[0], &var_array_const[1], &var_array_const[2]};


void update_variables(unsigned long *arr[]) {
  int i = 0;
  for(i=0; i < sizeof(var_array)/sizeof(unsigned long*); i++) {
    *arr[i] = (i+1)* (i+1);
  }
}


int main() {
  update_variables(var_array);
  printf("global_var1 : %lx\n", global_var1);
  printf("global_var2 : %lx\n", global_var2);
  printf("global_var3 : %lx\n", global_var3);
  printf("global_var4 : %lx\n", global_var4);

  printf("*var_test.a : %lx\n", *var_test.a);
  printf("*var_test.b : %lx\n", *var_test.b);
  printf("*var_test.c : %lx\n", *var_test.c);

  printf("arr_test.a : %lx\n", *arr_test.a);
  printf("arr_test.b : %lx\n", *arr_test.b);
  printf("arr_test.c : %lx\n", *arr_test.c);

  return 0;
}



