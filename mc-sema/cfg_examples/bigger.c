
int g_updt = 0;

int update(int k)
{
  if(k > g_updt) 
  {
    g_updt = k;
    return 1;
  } else 
  {
    return 0;
  }
}
