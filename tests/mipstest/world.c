#include <stdio.h>
#include <stdlib.h>

void try(int);

int pwd = 10;

void try(int x)
{
  if (x==pwd)
    puts("This\n");
  else 
    puts("That\n");
  
  return;
}

int main()
{
  char buf[6] ;
  int i;
  puts("enter integer");
  fgets(buf,sizeof(buf),stdin);

  i = atoi(buf);

  try(i);
  return 0;
}
