#pragma once

#include <string>
#include <vector>
#include <unordered_map>

#include <CodeObject.h>

#include <CFG.pb.h>

class ExternalFunction;

struct MagicSection {
  mcsema::ExternalVariable *WriteExternalVariable(mcsema::Module &module,
                                                  const std::string &name="");
  mcsema::ExternalFunction *WriteExternalFunction(mcsema::Module &module,
                             ExternalFunction &function);

  Dyninst::Address AllocSpace(uint64_t byte_width=8);

  //TODO(lukas): Rework as ctor
  void init(Dyninst::Address start_ea, int ptr_byte_size=8) {
    this->start_ea = start_ea;
    this->ptr_byte_size = ptr_byte_size;
  }

  std::string name = "magic_section";
  std::stringstream data;
  Dyninst::Address start_ea = 0;
  uint64_t size = 0;
  int ptr_byte_size = 8;

  std::vector<mcsema::ExternalVariable *> ext_vars;
  std::vector<mcsema::ExternalFunction *> ext_funcs;

  // This will serve when searching for function xrefs, IDA uses everywhere
  // imaginary address while Dyninst catches the .plt stub one
  std::unordered_map<Dyninst::Address, Dyninst::Address> real_to_imag;

};
