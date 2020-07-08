/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "Util.h"

mcsema::CodeReference *AddCodeXref(mcsema::Instruction * instruction,
                 mcsema::CodeReference_OperandType opTy,
                 Dyninst::Address addr) {

    auto xref = instruction->add_xrefs();
    xref->set_operand_type(opTy);
    xref->set_ea(addr);
    return xref;
}
