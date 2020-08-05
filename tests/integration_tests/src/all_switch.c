/* TAGS: min c */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/* TEST: 12 */
/* TEST: 15 */
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

int main(int argc, const char *argv[]) {

	if(argc < 2) {
		return -1;
	}

	int input = atoi(argv[1]);

	switch(input) {
		case 0: 
			printf("Input was zero\n");
			break;
		case 1: 
			printf("Input was one\n");
			break;
		case 2: 
			printf("Input was two\n");
			break;
		case 4: 
			printf("Input was four\n");
			break;
		case 6: 
			printf("Input was six\n");
			break;
		case 12: 
			printf("Input was twelve\n");
			break;
		case 13: 
			printf("Input was thirteen\n");
			break;
		case 19: 
			printf("Input was nineteen\n");
			break;
		case 255: 
			printf("Input was two hundred fifty-five\n");
			break;
		case 0x12389:
			printf("Really big input:  0x12389\n");
			break;
		case 0x1238A:
			printf("Really big input:  0x1238A\n");
			break;
		case 0x1238B:
			printf("Really big input:  0x1238B\n");
			break;
		case 0x1238C:
			printf("Really big input:  0x1238C\n");
			break;
		case 0x1238D:
			printf("Really big input:  0x1238D\n");
			break;
		case 0x1238F:
			printf("Really big input:  0x1238F\n");
			break;
		case 0x12390:
			printf("Really big input:  0x12390\n");
			break;
		case 0x12391:
			printf("Really big input:  0x12391\n");
			break;
		case 0x12392:
			printf("Really big input:  0x12392\n");
			break;
		case 0x12393:
			printf("Really big input:  0x12393\n");
			break;
		default:
			printf("Unknown input: %d\n", input);
	}
	return 0;
}
