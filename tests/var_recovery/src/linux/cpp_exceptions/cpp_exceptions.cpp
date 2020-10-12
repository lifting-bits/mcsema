#include <cstdlib>
#include <iostream>
#include <stdexcept>

bool is_admin = false;

void set_admin(int uid) {
  is_admin = 0 == uid;
}

int sum_of_squares(int a, int b) {
  int a2 = a * a;
  int b2 = b * b;
  return a2 + b2;
}

int main(int argc, const char *argv[]) {

  std::cout << "Starting example program\n";

  try {
    if (argc != 3) {
      throw std::out_of_range("Supply two arguments, please");
    }
    int a = std::atoi(argv[1]);
    int b = std::atoi(argv[2]);

    if (a == b && b == 5) {
      throw std::runtime_error("Lucky number 5");
    }

    set_admin(sum_of_squares(a, b));

    std::cout << "You are " << (is_admin ? "now" : "not") << " admin.\n";
  } catch (std::out_of_range &e) {
    std::cerr << "Index out of range: " << e.what() << std::endl;
    return 1;
  } catch (std::runtime_error &e) {
    std::cerr << "Runtime error: " << e.what() << std::endl;
    return 1;
  } catch (...) {
    std::cerr << "An unknown exception occurred!\n";
    return 1;
  }

  return 0;
}
