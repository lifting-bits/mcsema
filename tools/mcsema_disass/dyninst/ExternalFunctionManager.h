#pragma once

#include <CFG.pb.h>

#include <istream>
#include <unordered_map>
#include <set>
#include <string>
#include <experimental/optional>
#include <memory>

class ExternalFunctionManager;
extern std::unique_ptr<ExternalFunctionManager> gExtFuncManager;

struct ExternalFunction {
  using CfgCC = mcsema::ExternalFunction::CallingConvention;

  enum class CallingConvention {
    CallerCleanup = 0,
    CalleeCleanup = 1,
    FastCall = 2
  };

  std::string symbol_name;
  CallingConvention cc = CallingConvention::CallerCleanup;
  bool has_return = true;
  std::int32_t arg_count = 0;
  bool is_weak = false;
  std::experimental::optional<std::string> signature = {};

  // Dyninst::Address
  uint64_t ea = 0;
  uint64_t imag_ea = 0;
  CfgCC CfgCallingConvention() const;

  mcsema::ExternalFunction *Write(mcsema::Module &module);
  mcsema::ExternalFunction *WriteHelper(mcsema::Module &module, uint64_t ea);
};

class ExternalFunctionManager {
public:
  /* The following methods can be used to register external
   * functions with the ExternalFunctionManager. If the same name is
   * used multiple times, the information will be overwritten.
   */

  // Registers a function called "name" with info "func"
  void AddExternalSymbol(const std::string &name, const ExternalFunction &func);

  // Parses s as if it were a line in a function definitions file
  void AddExternalSymbol(const std::string &s);

  // Reads from s as if it were a function definitions file
  void AddExternalSymbols(std::istream &s);

  // Un-mark a function as external
  void RemoveExternalSymbol(const std::string &name);

  // Returns true iff the function called "name" is external
  bool IsExternal(const std::string &name) const;

  // Returns the information stored for the function called "name"
  // and LOG(FATAL) if no such function can be found.
  ExternalFunction &GetExternalFunction(const std::string &name);

  /* The following methods can be used to keep track of the external
   * functions that are actually called somewhere. This can greatly
   * reduce the external_funcs blocks in the CFG file.
   */
  void ClearUsed();
  void MarkAsUsed(const std::string &name);
  std::vector<ExternalFunction> GetAllUsed( std::vector<std::string>& uknowns) const;

private:
  std::unordered_map<std::string, ExternalFunction> external_funcs;
  std::set<std::string> used_funcs;
};