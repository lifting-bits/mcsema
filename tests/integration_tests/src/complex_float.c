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
  float complex beg = 4.54 + 2.56*I;
  float complex z = cexpf(beg);

  float img = cimagf(z);
  float real = crealf(z);

  int i_img = (int) img;
  int i_real = (int) real;

  printf("%i %i\n", (int) real, (int) i_img);
  if ( i_img != 2 ) printf("NOK img!\n");
  if ( i_real != 4 ) printf("NOK real!\n");

  printf("%i\n\t%i + %i\n", 42, (int)real, (int)img);

}
