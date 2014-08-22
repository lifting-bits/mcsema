int main(int hInstance, int hPrevInstance, char* lpCmdLine, int nCmdShow) {
  int x = nCmdShow;
  switch (lpCmdLine[0]) {
  case 'a':
  x = x + 5;
  case 'b':
  x = x / 2;
  break;
  case 'z':
  x = x * 5;
  break;
  case '5':
  x = 2;
  break;
  case 'B':
  x = 487 - 2*x;
  break;
  case 'l':
  x = 22 + 213 / x - x * x;
  break;
  default:
  x = -1;
  }
  return 622 * x - 3;
}
