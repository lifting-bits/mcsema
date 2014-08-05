//gcc -m32 -c -o insertionsort.o insertionsort.c
#include <stdio.h>
#include <math.h>
#include <limits.h>

void insertion(int a[], int N) 
{ 
  int i, j, ai;
  int comparisons = 0;
  a[0] = -INT_MAX; 

  for(i=2; i <= N; i++)
  {
    ai = a[i];
    j = i-1;
    while( a[j] > ai )
    {
      comparisons++;
      a[j+1] = a[j];
      j--;
    }

    a[j+1] = ai;
  }

  return;
}

int main(int argc, char *argv[])
{
    int foo[] = {0, 60, 50, 40, 30, 100, 90, 20, 10, 80, 70};
    int foo2[] = {0, 2, 1, 4, 3, 6, 5, 8, 7, 10, 9};
    int foo3[] = {0, 2, 1, 4, 3, 6, 5};
    int foo4[] = {0, 9, 10, 7, 8, 5, 6, 3, 4, 1, 2};
    int foo5[] = {0, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    int foo6[] = {0, 9, 10, 7, 8, 5, 6};
    int foo7[] = {0, 9, 10, 7, 8, 5, 6, 3, 4};
    int i;
    
    insertion(foo, 10);

    insertion(foo2, 10);

    insertion(foo3, 6);

    insertion(foo4, 10);

    insertion(foo5, 10);

    insertion(foo6, 6);

    insertion(foo7, 8);

    /*for(i = 1; i <= 10; i++)
    {
        printf("%d ", foo[i]);
    }

    printf("\n");*/

    return 0; 
}
