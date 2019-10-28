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
#include <stdio.h>
#include <math.h>
#include <float.h>

int main(void)
{
  double complex z = 2 + 2*I;
  double complex res = cexp( z );

  double img = cimag(res);
  double real = creal(res);

  int i_img = (int) img;

  printf("%i %i\n", (int) real, (int) img);
  if ( i_img != 6 ) printf("NOK!\n");

  printf("%i\n\t%i + %ii\n", 42, (int)real, (int)img);

}
