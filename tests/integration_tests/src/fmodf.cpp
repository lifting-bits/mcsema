/* TAGS: min cpp */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
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

#include <float.h>
#include <math.h>
#include <stdio.h>

void do_calc(float first, float second) {
  float result = fmodf(first, second);
  printf("%i\n", (int) result);
  if (fabsf(result - 0.4f) < FLT_EPSILON)
    printf("Okay.\n");
  else
    printf("Nok.\n");
}

int main() {
  printf("Begin %i %i %i\n\t***\n", (int) 123.456f, 2, 4);
  float fix = 5.4f;
  for (float i = 0.1f; i <= 0.5f; i += 0.1f) {
    do_calc(fix, i);
  }
}
