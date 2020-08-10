/* TAGS: min cpp */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/* TEST: 42 */
/* TEST: -543 */
/* TEST: 21 */
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

#include <iostream>

template <typename FuncPtr, typename Num = int>
int specialSum(Num *arr, int size, FuncPtr ptr, int base = 0) {
  int result = base;
  for (int i = 0; i < size; ++i) {
    result = ptr(result, arr[i]);
  }
  return result;
}


int add(int a, int b) {
  return a + b;
}

int dec(int a, int b) {
  return a - 1;
}

int joker(int a, int b) {
  if (a > b)
    return dec(a, b);
  if (a < b)
    return add(a, b);
  return 0;
}

template <typename ordFunc, typename getFunc>
auto specialFunc(ordFunc ord, getFunc get, int input) {
  int salt = 42;

  auto g = get(input, salt);
  int arr[3] = {input, salt, g};

  if (specialSum(arr, 3, ord) > 0)
    return add;
  else
    return dec;
}

int main(int argc, char *argv[]) {
  int arr[10] = {1, 4, 32, -54, 5, 6, 76, 12, 45, -89};
  int res = specialSum(arr, 10, add);
  printf("%i\n", res);

  res = specialSum(arr, 10, dec);
  printf("%i\n", res);

  res = specialSum(arr, 10, joker);
  printf("%i\n", res);

  auto special = specialFunc(add, dec, std::stoi(argv[1]));
  printf("%i\n", special(37, 5));
}
