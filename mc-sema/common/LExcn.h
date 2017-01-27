#ifndef _L_EXCN_H
#define _L_EXCN_H
#include <string>
#include <exception>
#include <iostream>
#include <sstream>

class LErr : public std::exception {
private:
  std::string message;
public:
  LErr(unsigned int line, const char *file, std::string message) {
    std::stringstream ss;
    ss << "Generic error: Line: " << line << "\n"
       << "File: " << file << "\n" << message;
    this->message = ss.str();
  }
  virtual ~LErr(void) throw() { }

  virtual const char *what() const throw() {
    return this->message.c_str();
  }
};

#define LASSERT(cond, msg) if(!(cond)) throw LErr(__LINE__, __FILE__, msg); 

#define D(X)

#endif //_L_EXCN_H
