#ifndef _L_EXCN_H
#define _L_EXCN_H
#include <string>
#include <exception>
#include <iostream>
#include <sstream>
#include <boost/exception/to_string.hpp>

class LErr : public std::exception {
private:
  std::string message;
public:
  LErr(unsigned int line, const char *file, std::string message) {
    this->message = "Generic error: Line: " + 
                    boost::to_string<unsigned int>(line) + "\n" +
                    "File: " + std::string(file) + "\n" +
                    message;
  }
  virtual ~LErr(void) throw() { }

  virtual const char *what() const throw() {
    return this->message.c_str();
  }
};

#define LASSERT(cond, msg) if(!(cond)) throw LErr(__LINE__, __FILE__, msg); 

#endif //_L_EXCN_H
