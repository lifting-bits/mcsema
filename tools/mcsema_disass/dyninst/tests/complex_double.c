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
  
  printf("%f\n\t%f + %fi\n", 42.42f, real, img);

}
