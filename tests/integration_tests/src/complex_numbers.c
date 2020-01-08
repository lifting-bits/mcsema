/* TAGS: min c */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/* LD_OPTS: -lm */
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

#include <complex.h>
#include <math.h>
#include <stdio.h>

void FooFloat() {
  float complex initial_value = 3.14f + 4.2*I;
  float complex exponent = 2.0f - 1.12*I;
  float complex result = cpowf(initial_value, exponent);

  float real_part = crealf(result);
  float imag_part = cimagf(result);

  int int_real = (int) real_part;
  int int_imag = (int) imag_part;
  printf("%i %i\n", int_real, int_imag);
  if (int_real == 77 && int_imag == 0) puts("Okay");
  else puts("Nok");

  result = csinf(initial_value);

  real_part = crealf(result);
  imag_part = cimagf(result);

  int_real = (int) real_part;
  int_imag = (int) imag_part;
  printf("%i %i\n", int_real, int_imag);

  if (int_real == 0 && int_imag == -33) puts("Okay");
  else puts("Nok");
}

void FooDouble() {
  double complex initial_value = 3.14 + 4.2*I;
  double complex exponent = 2.0f - 1.12*I;
  double complex result = cpow(initial_value, exponent);

  double real_part = creal(result);
  double imag_part = cimag(result);

  int int_real = (int) real_part;
  int int_imag = (int) imag_part;
  printf("%i %i\n", int_real, int_imag);
  if (int_real == 77 && int_imag == 0) puts("Okay");
  else puts("Nok");

  result = csin(initial_value);

  real_part = creal(result);
  imag_part = cimag(result);

  int_real = (int) real_part;
  int_imag = (int) imag_part;

  printf("%i %i\n", int_real, int_imag);
  if (int_real == 0 && int_imag == -33) puts("Okay");
  else puts("Nok");
}

int main(void)
{
  FooFloat();
  FooDouble();
  //TODO: Crashing with floating point exception
  //FooLongDouble();
}
