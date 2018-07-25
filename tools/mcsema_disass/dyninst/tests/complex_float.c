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
  
  printf("%f\n\t%f + %fi\n", 42.42f, real, img);

}
