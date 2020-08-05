/* TAGS: min cpp */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/* TEST: 23 */
/* TEST: 43 */
/* TEST: 435 */


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
#include <stdlib.h>

int zero() {
  return 0;
}

int one() {
  return 1;
}

int two() {
  return 2;
}

int four() {
  return 4;
}

int many() {
  return 42;
}


using zTy = int (*)();

template <typename baseTy>
using fTy = int(baseTy *, size_t, int);


int compare(const void *a, const void *b) {
  printf("Comparing:\n");
  zTy arg1 = *(zTy *) a;
  printf("\tArg1 %i\n", arg1());

  zTy arg2 = *(zTy *) b;
  printf("\tArg2 %i\n", arg2());

  int rhs = arg1();
  int lhs = arg2();
  if (rhs < lhs)
    return -1;
  if (rhs > lhs)
    return 1;
  return 0;
}

template <typename Func>
int firstLevel(Func *f, size_t size, int iter) {
  int base = f[0]();
  for (auto i = 0U; i < iter; ++i) {
    base += f[i % size]();
    printf("Iter: %i \tbase: %i\n", i, base);
  }

  printf("Before sort:\n");
  for (auto i = 0U; i < size; ++i) {
    printf("\t%i", f[i]());
  }
  printf("\n");

  qsort(f, size, sizeof(zTy), compare);
  printf("Sorted:\n");
  for (auto i = 0U; i < size; ++i) {
    printf("\t%i", f[i]());
  }
  printf("\n");
  return base;
}

int main(int argc, char *argv[]) {
  int a = atoi(argv[1]);
  int (*funcs[])() = {two, many, four, zero, one};
  int result = firstLevel<int (*)()>(funcs, 5, a);
}
