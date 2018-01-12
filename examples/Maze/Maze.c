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

/*
 * It's a maze!
 * Use a,s,d,w to move "through" it.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Dimensions of the Maze */
enum {
  kWidth = 11,
  kHeight = 7
};

/* Hard-coded maze */
char maze[kHeight][kWidth] = {
    {'+', '-', '+', '-', '-', '-', '+', '-', '-', '-', '+'},
    {'|', ' ', '|', ' ', ' ', ' ', ' ', ' ', '|', '#', '|'},
    {'|', ' ', '|', ' ', '-', '-', '+', ' ', '|', ' ', '|'},
    {'|', ' ', '|', ' ', ' ', ' ', '|', ' ', '|', ' ', '|'},
    {'|', ' ', '+', '-', '-', ' ', '|', ' ', '|', ' ', '|'},
    {'|', ' ', ' ', ' ', ' ', ' ', '|', ' ', ' ', ' ', '|'},
    {'+', '-', '-', '-', '-', '-', '+', '-', '-', '-', '+'},
};

/**
 * Draw the maze state in the screen!
 */
void draw(void) {
  int i, j;
  for (i = 0; i < kHeight; i++) {
    for (j = 0; j < kWidth; j++) {
      printf("%c", maze[i][j]);
    }
    printf("\n");
  }
  printf("\n");
}

enum {
  kMaxNumPlayerMoves = 28
};

/**
 * The main function
 */
int main(int argc, char *argv[]) {
  int x, y;     /* Player position */
  int ox, oy;   /* Old player position */
  int i = 0;    /* Iteration number */

  char program[kMaxNumPlayerMoves];

  /* Initial position */
  x = 1;
  y = 1;
  maze[y][x] = 'X';

  /* Print some info. */
  printf("Maze dimensions: %dx%d\n", kWidth, kHeight);
  printf("Player position: %dx%d\n", x, y);
  printf("Iteration no. %d\n", i);
  printf("Program the player moves with a sequence of 'w', 's', 'a' and 'd'\n");
  printf("Try to reach the price(#)!\n");

  /* Draw the maze */
  draw();

  /* Read the directions 'program' to execute... */
  read(STDIN_FILENO, program, kMaxNumPlayerMoves);

  /* Iterate and run 'program'. */
  while (i < kMaxNumPlayerMoves) {
    /* Save old player position */
    ox = x;
    oy = y;

    /* Move player position depending on the actual command */
    switch (program[i]) {
      case 'w':
        y--;
        break;
      case 's':
        y++;
        break;
      case 'a':
        x--;
        break;
      case 'd':
        x++;
        break;
      default:
        printf("Wrong command, only w,s,a,d are accepted!)\n");
        printf("You lose!\n");
        exit(EXIT_FAILURE);
    }

    /* If hit the price, You Win!! */
    if (maze[y][x] == '#') {
      printf("You win!\n");
      printf("Your solution <%42s>\n", program);
      exit(EXIT_SUCCESS);
    }

    /* If something is wrong do not advance. */
    if (maze[y][x] != ' '
        && !((y == 2 && maze[y][x] == '|' && x > 0 && x < kWidth))) {
      x = ox;
      y = oy;
    }

    /* Print new maze state and info... */
    printf("Player position: %dx%d\n", x, y);
    printf("Iteration no. %d. Action: %c. %s\n", i, program[i],
           ((ox == x && oy == y) ? "Blocked!" : ""));

    /* If crashed to a wall! Exit, you lose */
    if (ox == x && oy == y) {
      printf("You lose\n");
      exit(EXIT_FAILURE);
    }

    /* put the player on the maze... */
    maze[y][x] = 'X';

    /* draw it */
    draw();

    /* increment iteration */
    i++;

    /* me wait to human */
    sleep(1);
  }

  /* You couldn't make it! You lose! */
  printf("You lose\n");
  return EXIT_FAILURE;
}
