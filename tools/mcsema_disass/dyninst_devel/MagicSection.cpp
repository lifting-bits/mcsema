#include "MagicSection.h"

#include "ExternalFunctionManager.h"

#include <glog/logging.h>

mcsema::ExternalVariable *MagicSection::WriteExternalVariable(
    mcsema::Module &module,
		const std::string &name) {
  CHECK(start_ea) << "Magic section cannot start with 0!";

	Dyninst::Address unreal_ea = AllocSpace(ptr_byte_size);

	LOG(INFO) << "External var " << name
						<< " is in magic_section at " << unreal_ea;
	auto external_var = module.add_external_vars();
	external_var->set_name(name);
	external_var->set_ea(unreal_ea);

	external_var->set_size(ptr_byte_size);

	//TODO(lukas): This needs some checks
	external_var->set_is_weak(false);
	external_var->set_is_thread_local(false);

	ext_vars.push_back(external_var);

	return external_var;
}

mcsema::ExternalFunction *MagicSection::WriteExternalFunction(
    mcsema::Module &module,
    ExternalFunction &function) {
  CHECK(start_ea) << "Magic section cannot start with 0!";

	Dyninst::Address unreal_ea = AllocSpace(ptr_byte_size);
	function.imag_ea = unreal_ea;
  real_to_imag.insert({function.ea, unreal_ea});
	ext_funcs.push_back(function.Write(module));
  return ext_funcs.back();
}

Dyninst::Address MagicSection::AllocSpace(uint64_t byte_width) {
	Dyninst::Address unreal_ea = start_ea + size;
	size += ptr_byte_size;
	for (int i = 0; i < ptr_byte_size; ++i) {
		data << "\0";
	}

	return unreal_ea;
}

Dyninst::Address MagicSection::GetAllocated(Dyninst::Address ea) {
  auto entry = real_to_imag.find(ea);
  CHECK(entry == real_to_imag.end())
      << "Trying to get magicSection address for not registered ea";
  return entry->second;
}
