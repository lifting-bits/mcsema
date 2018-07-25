#include <complex.h>
#include <stdio.h>
#include <math.h>
#include <float.h>

int main(void)
{
  long double complex z = 1.25 + 2.54*I;
  long double complex res = cexpl( z );
  
  
  long double img = cimagl(res); 
  long double real = creall(res);
 
  if ( real + 2.877  < 0 
      && real + 2.8776 > 0
      && img - 1.975 > 0
      && img - 1.976 < 0 )
    printf( "OK\n" );
  else
    printf( "NOK\n" );

  printf("%f\n\t%Lf + %Lfi\n", 42.42f, real, img);
}
